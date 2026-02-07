use crate::bindings::rest_client::{
	encode_query_params, HttpMethod, RestClient, RestClientOptions, RestResponse,
};
use crate::bindings::suspendable_rest_client::SuspensionBehavior;
use crate::element_value::{ElementValue, ParsedEntity};
use crate::entities::entity_facade::{ID_FIELD, PERMISSIONS_FIELD};
use crate::entities::generated::base::PersistenceResourcePostReturn;
use crate::entities::generated::storage::{BlobAccessTokenPostIn, BlobServerAccessInfo};
use crate::entities::Entity;
use crate::id::id_tuple::{BaseIdType, IdTupleType, IdType};
use crate::instance_mapper::InstanceMapper;
use crate::json_element::{JsonElement, RawEntity};
use crate::json_serializer::InstanceMapperError::TypeNotFound;
use crate::json_serializer::JsonSerializer;
use crate::metamodel::{ElementType, TypeModel};
use crate::rest_error::HttpError;
use crate::type_model_provider::TypeModelProvider;
use crate::util::extract_parsed_entity_id;
use crate::GeneratedId;
use crate::{ApiCallError, CustomId, HeadersProvider, ListLoadDirection, TypeRef};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use crypto_primitives::randomizer_facade::RandomizerFacade;
use std::sync::Arc;

/// A high level interface to manipulate unencrypted entities/instances via the REST API
pub struct EntityClient {
	rest_client: Arc<dyn RestClient>,
	base_url: String,
	auth_headers_provider: Arc<HeadersProvider>,
	json_serializer: Arc<JsonSerializer>,
	pub type_model_provider: Arc<TypeModelProvider>,
}

impl EntityClient {
	pub(crate) fn new(
		rest_client: Arc<dyn RestClient>,
		json_serializer: Arc<JsonSerializer>,
		base_url: String,
		auth_headers_provider: Arc<HeadersProvider>,
		type_model_provider: Arc<TypeModelProvider>,
	) -> Self {
		EntityClient {
			rest_client,
			json_serializer,
			base_url,
			auth_headers_provider,
			type_model_provider,
		}
	}

	#[allow(clippy::unused_async, unused)]
	/// Gets an entity/instance of type `type_ref` from the backend
	pub async fn load<Id: IdType>(
		&self,
		type_ref: &TypeRef,
		id: &Id,
	) -> Result<ParsedEntity, ApiCallError> {
		let client_type_model = self.resolve_client_type_ref(type_ref)?;
		if client_type_model.element_type == ElementType::BlobElement {
			return self.load_blob_element(type_ref, id).await;
		}

		let url = format!(
			"{base_url}/rest/{appname}/{typename}/{id}",
			base_url = self.base_url,
			appname = type_ref.app,
			id = id,
			typename = self
				.type_model_provider
				.resolve_client_type_ref(type_ref)
				.ok_or_else(|| TypeNotFound {
					type_ref: type_ref.clone(),
				})?
				.name,
		);
		let response_bytes = self
			.prepare_and_fire(type_ref, url)
			.await?
			.expect("no body");
		let response_entity =
			serde_json::from_slice::<RawEntity>(response_bytes.as_slice()).unwrap();
		let parsed_entity = self.json_serializer.parse(type_ref, response_entity)?;
		Ok(parsed_entity)
	}

	async fn load_blob_element<Id: IdType>(
		&self,
		type_ref: &TypeRef,
		id: &Id,
	) -> Result<ParsedEntity, ApiCallError> {
		let client_type_model = self.resolve_client_type_ref(type_ref)?;
		assert_eq!(
			client_type_model.element_type,
			ElementType::BlobElement,
			"load_blob_element called for non-blob element type"
		);

		let id_str = id.to_string();
		let mut parts = id_str.split('/');
		let Some(archive_id_str) = parts.next() else {
			return Err(ApiCallError::internal("missing archive id".to_string()));
		};
		let Some(element_id_str) = parts.next() else {
			return Err(ApiCallError::internal("missing element id".to_string()));
		};
		if parts.next().is_some() {
			return Err(ApiCallError::internal(
				"invalid blob element id (expected '<archive>/<element>')".to_string(),
			));
		}

		let archive_id: GeneratedId = archive_id_str.to_string().into();
		let element_id = element_id_str.to_string();
		let model_version = client_type_model.version;

		// Try twice: a second run helps if the token was already expired.
		for _attempt in 0..2 {
			let access_info = self.request_read_token_archive(&archive_id).await?;
			let mut query_params: Vec<(String, String)> = vec![
				("ids".to_owned(), element_id.clone()),
				(
					"blobAccessToken".to_owned(),
					access_info.blobAccessToken.clone(),
				),
			];
			query_params.extend(
				self.auth_headers_provider
					.provide_headers(model_version)
					.into_iter(),
			);
			let encoded_query = encode_query_params(query_params);

			let type_name = client_type_model.name.to_lowercase();
			for server in access_info.servers {
				let base_url = Self::origin_url(&server.url);
				let url = format!(
					"{}/rest/{}/{}/{}{}",
					base_url, type_ref.app, type_name, archive_id, encoded_query
				);
				let sanitized_url = Self::sanitize_url(&url);

				let response = match self
					.rest_client
					.request_binary(
						url,
						HttpMethod::GET,
						RestClientOptions {
							headers: Default::default(),
							body: None,
							suspension_behavior: Some(SuspensionBehavior::Suspend),
						},
					)
					.await
				{
					Ok(r) => r,
					Err(_e) => continue,
				};

				self.ensure_latest_server_model(&response).await?;

				match response.status {
					200..=299 => {
						let bytes = response.body.clone().expect("no body");
						let entities = serde_json::from_slice::<Vec<RawEntity>>(bytes.as_slice())
							.map_err(|e| {
							ApiCallError::internal_with_err(e, "invalid blob element response")
						})?;
						let Some(first) = entities.into_iter().next() else {
							return Err(ApiCallError::ServerResponseError {
								source: HttpError::NotFoundError,
							});
						};
						return Ok(self.json_serializer.parse(type_ref, first)?);
					},
					_ => {
						let http_error =
							HttpError::from_http_response(response.status, &response.headers)?;
						if http_error == HttpError::BadRequestError {
							let body_str = response
								.body
								.as_deref()
								.map(|b| String::from_utf8_lossy(b).to_string())
								.unwrap_or_default();
							let body_str = Self::sanitize_error_body(&body_str);
							return Err(ApiCallError::internal(format!(
								"blob element request failed: status=400 url={sanitized_url} body={body_str}"
							)));
						}
						match http_error {
							HttpError::ConnectionError
							| HttpError::InternalServerError
							| HttpError::NotFoundError => continue,
							HttpError::NotAuthorizedError => break,
							other => {
								return Err(ApiCallError::ServerResponseError { source: other });
							},
						}
					},
				}
			}
		}

		Err(ApiCallError::internal(
			"could not load blob element from any server".to_string(),
		))
	}

	/// Extract the origin from a URL string (scheme + authority).
	///
	/// Blob server URLs can contain path segments; the TS client overwrites the pathname when
	/// constructing the request URL. For parity, we drop any path/query/fragment here.
	fn origin_url(url: &str) -> &str {
		let trimmed = url.trim_end_matches('/');
		let Some(scheme_idx) = trimmed.find("://") else {
			return trimmed;
		};
		let after_scheme = scheme_idx + 3;
		let Some(path_idx) = trimmed[after_scheme..].find('/') else {
			return trimmed;
		};
		&trimmed[..after_scheme + path_idx]
	}

	fn sanitize_url(url: &str) -> String {
		let Some((base, query)) = url.split_once('?') else {
			return url.to_string();
		};
		let mut out = Vec::new();
		for pair in query.split('&') {
			let Some((k, v)) = pair.split_once('=') else {
				continue;
			};
			if k == "accessToken" || k == "blobAccessToken" {
				out.push(format!("{k}=<redacted>"));
			} else {
				out.push(format!("{k}={v}"));
			}
		}
		format!("{base}?{}", out.join("&"))
	}

	fn sanitize_error_body(body: &str) -> String {
		let mut s = body.replace("accessToken", "accessToken(<redacted>)");
		s = s.replace("blobAccessToken", "blobAccessToken(<redacted>)");
		let limit = 2048;
		if s.len() > limit {
			s.truncate(limit);
			s.push_str("...<truncated>");
		}
		s
	}

	async fn request_read_token_archive(
		&self,
		archive_id: &GeneratedId,
	) -> Result<crate::entities::generated::storage::BlobServerAccessInfo, ApiCallError> {
		let model_version = self
			.resolve_client_type_ref(&BlobAccessTokenPostIn::type_ref())?
			.version;
		let mut headers = self.auth_headers_provider.provide_headers(model_version);
		headers.insert("Content-Type".to_owned(), "application/json".to_owned());

		// IMPORTANT: associations are represented as arrays on the wire.
		// Using serde_json on typed structs would serialize aggregations as objects, which the
		// backend rejects with 400.
		let read_id = CustomId(
			BASE64_URL_SAFE_NO_PAD
				.encode(RandomizerFacade::from_core(rand_core::OsRng).generate_random_array::<4>()),
		);
		let body_json = serde_json::json!({
			"78": 0,
			"180": serde_json::Value::Null,
			"80": [],
			"181": [
				{
					"176": read_id.to_string(),
					"177": archive_id.to_string(),
					"178": serde_json::Value::Null,
					"179": []
				}
			]
		});
		let url = format!("{}/rest/storage/blobaccesstokenservice", self.base_url);
		let body = serde_json::to_vec(&body_json).map_err(|e| {
			ApiCallError::internal_with_err(e, "failed to serialize blob token request")
		})?;

		let response = self
			.rest_client
			.request_binary(
				url,
				HttpMethod::POST,
				RestClientOptions {
					headers,
					body: Some(body),
					suspension_behavior: Some(SuspensionBehavior::Suspend),
				},
			)
			.await?;
		self.ensure_latest_server_model(&response).await?;
		match response.status {
			200..=299 => {
				let bytes = response.body.clone().expect("no body");
				let value =
					serde_json::from_slice::<serde_json::Value>(bytes.as_slice()).map_err(|e| {
						ApiCallError::internal_with_err(e, "invalid blob token response")
					})?;
				let Some(access_info_array) = value.get("161").and_then(|v| v.as_array()) else {
					return Err(ApiCallError::internal(
						"invalid blob token response: missing '161'".to_string(),
					));
				};
				let Some(first) = access_info_array.first() else {
					return Err(ApiCallError::internal(
						"invalid blob token response: empty '161'".to_string(),
					));
				};
				let info: BlobServerAccessInfo = serde_json::from_value(first.clone())
					.map_err(|e| ApiCallError::internal_with_err(e, "invalid access info"))?;
				Ok(info)
			},
			_ => {
				let http_error = HttpError::from_http_response(response.status, &response.headers)?;
				if http_error == HttpError::BadRequestError {
					let body_str = response
						.body
						.as_deref()
						.map(|b| String::from_utf8_lossy(b).to_string())
						.unwrap_or_default();
					let body_str = Self::sanitize_error_body(&body_str);
					return Err(ApiCallError::internal(format!(
						"blob access token request failed: status=400 body={body_str}"
					)));
				}
				Err(ApiCallError::ServerResponseError { source: http_error })
			},
		}
	}

	/// Returns the definition of an entity/instance type using the internal `TypeModelProvider`
	pub fn resolve_client_type_ref(&self, type_ref: &TypeRef) -> Result<&TypeModel, ApiCallError> {
		self.type_model_provider
			.resolve_client_type_ref(type_ref)
			.ok_or_else(|| {
				ApiCallError::internal(format!(
					"Model {:?} not found in client app {:?}",
					type_ref.type_id, type_ref.app
				))
			})
	}

	#[allow(clippy::unused_async, unused)]
	pub fn resolve_server_type_ref(
		&self,
		type_ref: &TypeRef,
	) -> Result<Arc<TypeModel>, ApiCallError> {
		self.type_model_provider
			.resolve_server_type_ref(type_ref)
			.ok_or_else(|| {
				ApiCallError::internal(format!(
					"Model {:?} not found in server app {:?}",
					type_ref.type_id, type_ref.app
				))
			})
	}

	/// Fetches and returns all entities/instances in a list element type
	#[allow(clippy::unused_async, unused)]
	pub async fn load_all(
		&self,
		type_ref: &TypeRef,
		list_id: &GeneratedId,
		direction: ListLoadDirection,
	) -> Result<Vec<ParsedEntity>, ApiCallError> {
		let mut min_id: String = if direction == ListLoadDirection::ASC {
			GeneratedId::min_id()
		} else {
			GeneratedId::max_id()
		}
		.to_string();
		let mut done = false;
		let mut load_all_result: Vec<ParsedEntity> = vec![];
		let type_model = self.resolve_client_type_ref(type_ref)?;

		let id_field_attribute_id: String = type_model
			.get_attribute_id_by_attribute_name(ID_FIELD)
			.map_err(|err| ApiCallError::InternalSdkError {
				error_message: format!(
					"{ID_FIELD} attribute does not exist on the type model with typeId {:?} {:?}",
					type_model.id, err
				),
			})?;

		while !done {
			let result = self
				.load_range(
					type_ref,
					list_id,
					&CustomId(min_id),
					1000,
					direction.clone(),
				)
				.await?;

			let Some(last_entity) = result.last() else {
				break;
			};

			let entity_id = last_entity
				.get(&id_field_attribute_id)
				.filter(|id| !matches!(id, ElementValue::Null))
				.ok_or_else(|| {
					ApiCallError::internal(
						"_id field have to be set while updating the instance".to_string(),
					)
				})?
				.clone();

			done = result.is_empty();
			min_id = extract_parsed_entity_id(type_ref, entity_id).1;
			load_all_result.extend(result);
		}

		Ok(load_all_result)
	}

	/// Fetches and returns a specified number (`count`) of entities/instances
	/// in a list element type starting at the index `start_id`
	#[allow(clippy::unused_async, unused)]
	pub async fn load_range<Id: BaseIdType>(
		&self,
		type_ref: &TypeRef,
		list_id: &GeneratedId,
		start_id: &Id,
		count: usize,
		direction: ListLoadDirection,
	) -> Result<Vec<ParsedEntity>, ApiCallError> {
		let type_model = self
			.type_model_provider
			.resolve_server_type_ref(type_ref)
			.ok_or_else(|| TypeNotFound {
				type_ref: type_ref.clone(),
			})?;
		assert_eq!(
			type_model.element_type,
			ElementType::ListElement,
			"cannot load range for non-list element"
		);
		let reverse = direction == ListLoadDirection::DESC;
		let url = format!(
			"{}/rest/{}/{}/{}?start={start_id}&count={count}&reverse={reverse}",
			self.base_url, type_ref.app, type_model.name, list_id
		);
		let response_bytes = self
			.prepare_and_fire(type_ref, url)
			.await?
			.expect("no body");
		let response_entities = serde_json::from_slice::<Vec<RawEntity>>(response_bytes.as_slice())
			.expect("invalid response");
		let parsed_entities = response_entities
			.into_iter()
			.map(|e| self.json_serializer.parse(type_ref, e))
			.collect::<Result<Vec<_>, _>>()?;
		Ok(parsed_entities)
	}

	#[allow(clippy::unused_async, unused)]
	async fn post_instance_changes(
		&self,
		parsed_entity: ParsedEntity,
		type_ref: &TypeRef,
		request_type: HttpMethod,
	) -> Result<RestResponse, ApiCallError> {
		let type_model = self.resolve_client_type_ref(type_ref)?;

		let mut request_url = format!(
			"{}/rest/{}/{}/",
			self.base_url, type_ref.app, type_model.name
		);
		let model_version = type_model.version;

		let id_field_attribute_id: String = type_model
			.get_attribute_id_by_attribute_name(ID_FIELD)
			.map_err(|err| ApiCallError::InternalSdkError {
				error_message: format!(
					"{ID_FIELD} attribute does not exist on the type model with typeId {:?} {:?}",
					type_model.id, err
				),
			})?;

		let entity_id = parsed_entity
			.get(&id_field_attribute_id)
			.filter(|id| !matches!(id, ElementValue::Null))
			.ok_or_else(|| {
				ApiCallError::internal(
					"_id field have to be set while updating the instance".to_string(),
				)
			})?
			.clone();

		let mut raw_entity = self.json_serializer.serialize(type_ref, parsed_entity)?;
		let (list_id, element_id) = extract_parsed_entity_id(type_ref, entity_id);

		if let Some(list_id) = list_id {
			request_url.push_str(list_id.as_str());
		}

		let permissions_field_attribute_id: String = type_model
			.get_attribute_id_by_attribute_name(PERMISSIONS_FIELD)
			.map_err(|err| ApiCallError::InternalSdkError {
				error_message: format!(
					"{PERMISSIONS_FIELD} attribute does not exist on the type model with typeId {:?} {:?}",
					type_model.id, err
				),
			})?;

		if request_type == HttpMethod::POST {
			raw_entity.insert(id_field_attribute_id, JsonElement::Null);
			raw_entity.insert(permissions_field_attribute_id, JsonElement::Null);
		} else {
			request_url.push('/');
			request_url.push_str(element_id.as_str());
		}

		let body = serde_json::to_vec(&raw_entity).map_err(|_| {
			ApiCallError::internal("Cannot serialize RawEntity to json".to_string())
		})?;
		let mut options = RestClientOptions {
			body: Some(body),
			headers: self.auth_headers_provider.provide_headers(model_version),
			suspension_behavior: Some(SuspensionBehavior::Suspend),
		};
		options
			.headers
			.insert("Content-Type".to_owned(), "application/json".to_owned());

		let response = self
			.rest_client
			.request_binary(request_url, request_type, options)
			.await?;

		self.ensure_latest_server_model(&response).await?;

		Ok(response)
	}

	#[allow(unused)]
	pub async fn create_instance(
		&self,
		type_ref: &TypeRef,
		parsed_entity: ParsedEntity,
		instance_mapper: &InstanceMapper,
	) -> Result<PersistenceResourcePostReturn, ApiCallError> {
		let response = self
			.post_instance_changes(parsed_entity, type_ref, HttpMethod::POST)
			.await?;

		assert!(
			response.status >= 200 && response.status <= 300,
			"non-ok status code"
		);

		let raw_response = response
			.body
			.as_deref()
			.and_then(|body| serde_json::from_slice(body).ok())
			.ok_or_else(|| {
				ApiCallError::internal("server did not responded with valid json".to_string())
			})?;

		let response_entity = self
			.json_serializer
			.parse(&PersistenceResourcePostReturn::type_ref(), raw_response)
			.map_err(|e| {
				ApiCallError::internal_with_err(
					e,
					"PersistenceResourcePostReturn returned by server is expected to be valid",
				)
			})?;

		let persistent_resource = instance_mapper
			.parse_entity(response_entity)
			.map_err(|_e| {
				ApiCallError::internal(
					"Cannot convert ParsedEntity to valid PersistenceResourcePostReturn"
						.to_string(),
				)
			})?;

		Ok(persistent_resource)
	}

	#[allow(unused)]
	pub async fn update_instance(
		&self,
		type_ref: &TypeRef,
		parsed_entity: ParsedEntity,
	) -> Result<(), ApiCallError> {
		let response = self
			.post_instance_changes(parsed_entity, type_ref, HttpMethod::PUT)
			.await?;
		assert!(
			response.status >= 200 && response.status <= 299,
			"non-ok status code {}",
			response.status
		);
		Ok(())
	}

	/// Deletes an existing single entity/instance on the backend
	#[allow(clippy::unused_async, unused)]
	pub async fn erase_element(
		&self,
		_type_ref: &TypeRef,
		_id: &GeneratedId,
	) -> Result<(), ApiCallError> {
		todo!("entity client erase_element")
	}

	/// Deletes an existing entity/instance of a list element type on the backend
	#[allow(clippy::unused_async, unused)]
	pub async fn erase_list_element<Id: IdTupleType>(
		&self,
		_type_ref: &TypeRef,
		_id: Id,
	) -> Result<(), ApiCallError> {
		todo!("entity client erase_list_element")
	}

	async fn prepare_and_fire(
		&self,
		type_ref: &TypeRef,
		url: String,
	) -> Result<Option<Vec<u8>>, ApiCallError> {
		let type_model = self.resolve_client_type_ref(type_ref)?;
		let model_version = type_model.version;
		let options = RestClientOptions {
			body: None,
			headers: self.auth_headers_provider.provide_headers(model_version),
			suspension_behavior: Some(SuspensionBehavior::Suspend),
		};
		let response = self
			.rest_client
			.request_binary(url, HttpMethod::GET, options)
			.await?;
		self.ensure_latest_server_model(&response).await?;

		match response.status {
			200..=299 => {
				// Ok
			},
			_ => {
				return Err(ApiCallError::ServerResponseError {
					source: HttpError::from_http_response(response.status, &response.headers)?,
				});
			},
		}

		Ok(response.body)
	}

	async fn ensure_latest_server_model(
		&self,
		response: &RestResponse,
	) -> Result<(), ApiCallError> {
		let current_model_hash = response
			.headers
			.get("app-types-hash")
			.map(|a| a.as_str())
			// if server did not put hash in response header,
			// always fetch application types again just to be safe
			.unwrap_or("");

		self.type_model_provider
			.clone()
			.ensure_latest_server_model(current_model_hash)
			.await
	}
}

#[cfg(test)]
mockall::mock! {
	pub EntityClient {
		pub fn new(
			rest_client: Arc<dyn RestClient>,
			json_serializer: Arc<JsonSerializer>,
			base_url: String,
			auth_headers_provider: Arc<HeadersProvider>,
			type_model_provider: Arc<TypeModelProvider>,
		) -> Self;
		pub fn get_type_model_provider() -> Arc<TypeModelProvider>;
		pub fn resolve_client_type_ref<'a>(&'a self, type_ref: &TypeRef) -> Result<&'a TypeModel, ApiCallError>;
		pub fn resolve_server_type_ref(&self, type_ref: &TypeRef) -> Result<Arc<TypeModel>, ApiCallError>;
		pub async fn load<Id: IdType>(
			&self,
			type_ref: &TypeRef,
			id: &Id,
		 ) -> Result<ParsedEntity, ApiCallError>;
		pub async fn load_all(
			&self,
			type_ref: &TypeRef,
			list_id: &GeneratedId,
			direction: ListLoadDirection,
		) -> Result<Vec<ParsedEntity>, ApiCallError>;
		pub async fn load_range<Id: BaseIdType>(
			&self,
			type_ref: &TypeRef,
			list_id: &GeneratedId,
			start_id: &Id,
			count: usize,
			list_load_direction: ListLoadDirection,
		) -> Result<Vec<ParsedEntity>, ApiCallError>;
		pub async fn setup_element(&self, type_ref: &TypeRef, entity: RawEntity) -> Vec<String>;
		pub async fn setup_list_element(
			&self,
			type_ref: &TypeRef,
			list_id: &GeneratedId,
			entity: RawEntity,
		) -> Vec<String>;
		pub async fn update(&self, type_ref: &TypeRef, entity: ParsedEntity) -> Result<(), ApiCallError>;
		pub async fn erase_element(&self, type_ref: &TypeRef, id: &GeneratedId) -> Result<(), ApiCallError>;
		pub async fn erase_list_element<Id: IdTupleType>(&self, type_ref: &TypeRef, id: Id) -> Result<(), ApiCallError>;
		async fn post_instance_changes( &self, parsed_entity: ParsedEntity, type_ref: &TypeRef, request_type: HttpMethod,
			) -> Result<RestResponse, ApiCallError>;
		pub async fn update_instance(&self, type_ref: &TypeRef, parsed_entity: ParsedEntity) -> Result<(), ApiCallError>;
		pub async fn create_instance(&self, type_ref: &TypeRef, parsed_entity: ParsedEntity, instance_mapper: &InstanceMapper)
			-> Result<PersistenceResourcePostReturn, ApiCallError>;
	}
}

#[cfg(test)]
mod stests {
	use super::*;
	use crate::bindings::rest_client::{MockRestClient, RestResponse};
	use crate::entities::Entity;
	use crate::metamodel::{AppName, TypeId};
	use crate::util::test_utils::*;
	use crate::CustomId;
	use crate::{collection, IdTupleCustom, IdTupleGenerated};
	use mockall::predicate::{always, eq};
	use serde::{Deserialize, Serialize};

	#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
	struct TestListGeneratedElementIdEntity {
		#[serde(rename = "101")]
		_id: IdTupleGenerated,
		#[serde(rename = "102")]
		field: String,
	}

	#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
	struct TestListCustomElementIdEntity {
		#[serde(rename = "201")]
		_id: IdTupleCustom,
		#[serde(rename = "202")]
		field: String,
	}

	impl Entity for TestListGeneratedElementIdEntity {
		fn type_ref() -> TypeRef {
			TypeRef {
				app: AppName::EntityClientTestApp,
				type_id: TypeId::from(10),
			}
		}
	}

	impl Entity for TestListCustomElementIdEntity {
		fn type_ref() -> TypeRef {
			TypeRef {
				app: AppName::EntityClientTestApp,
				type_id: TypeId::from(20),
			}
		}
	}

	#[tokio::test]
	async fn test_load_range_generated_element_id() {
		let type_provider = Arc::new(mock_type_model_provider());

		let list_id = GeneratedId("list_id".to_owned());
		let list_id_field_id = type_provider
			.resolve_server_type_ref(&TestListGeneratedElementIdEntity::type_ref())
			.expect("missing listentity")
			.get_attribute_id_by_attribute_name(ID_FIELD)
			.unwrap();
		let element_id_field_id = type_provider
			.resolve_server_type_ref(&TestListGeneratedElementIdEntity::type_ref())
			.expect("missing elemententity")
			.get_attribute_id_by_attribute_name("field")
			.unwrap();
		let entity_map: ParsedEntity = collection! {
			 list_id_field_id => ElementValue::IdTupleGeneratedElementId(IdTupleGenerated::new(list_id.clone(), GeneratedId("element_id".to_owned()))),
			element_id_field_id => ElementValue::Bytes(vec![1, 2, 3])
		};
		println!("{}", serde_json::to_string_pretty(&entity_map).unwrap());
		let mut rest_client = MockRestClient::new();
		let url = "http://test.com/rest/entityclienttestapp/TestListGeneratedElementIdEntity/list_id?start=zzzzzzzzzzzz&count=100&reverse=true";
		let json_folder = JsonSerializer::new(type_provider.clone())
			.serialize(
				&TestListGeneratedElementIdEntity::type_ref(),
				entity_map.clone(),
			)
			.unwrap();
		rest_client
			.expect_request_binary()
			.with(eq(url.to_owned()), eq(HttpMethod::GET), always())
			.return_once(move |_, _, _| {
				Ok(RestResponse {
					status: 200,
					headers: server_types_hash_header(),
					body: Some(serde_json::to_vec(&vec![json_folder]).unwrap()),
				})
			});

		let auth_headers_provider = HeadersProvider::new(Some("123".to_owned()));
		let entity_client = EntityClient::new(
			Arc::new(rest_client),
			Arc::new(JsonSerializer::new(type_provider.clone())),
			"http://test.com".to_owned(),
			Arc::new(auth_headers_provider),
			type_provider.clone(),
		);

		let result_entity = entity_client
			.load_range(
				&TestListGeneratedElementIdEntity::type_ref(),
				&list_id,
				&GeneratedId::max_id(),
				100,
				ListLoadDirection::DESC,
			)
			.await
			.expect("success");
		assert_eq!(result_entity, vec![entity_map]);
	}

	#[tokio::test]
	async fn test_load_range_custom_element_id() {
		let type_model_provider = Arc::new(mock_type_model_provider());

		let list_id = GeneratedId("list_id".to_owned());
		let id_field_id = type_model_provider
			.resolve_server_type_ref(&TestListCustomElementIdEntity::type_ref())
			.expect("custom id type not found")
			.get_attribute_id_by_attribute_name(ID_FIELD)
			.unwrap();
		let field_field_id = type_model_provider
			.resolve_server_type_ref(&TestListCustomElementIdEntity::type_ref())
			.expect("custom id type not found")
			.get_attribute_id_by_attribute_name("field")
			.unwrap();
		let entity_map: ParsedEntity = collection! {
			 id_field_id => ElementValue::IdTupleCustomElementId(IdTupleCustom::new(list_id.clone(), CustomId("element_id".to_owned()))),
			 field_field_id => ElementValue::Bytes(vec![1, 2, 3])
		};
		let mut rest_client = MockRestClient::new();
		let url = "http://test.com/rest/entityclienttestapp/TestListCustomElementIdEntity/list_id?start=zzzzzzzzzzzz&count=100&reverse=true";
		let json_folder = JsonSerializer::new(type_model_provider.clone())
			.serialize(
				&TestListCustomElementIdEntity::type_ref(),
				entity_map.clone(),
			)
			.unwrap();
		rest_client
			.expect_request_binary()
			.with(eq(url.to_owned()), eq(HttpMethod::GET), always())
			.return_once(move |_, _, _| {
				Ok(RestResponse {
					status: 200,
					headers: server_types_hash_header(),
					body: Some(serde_json::to_vec(&vec![json_folder]).unwrap()),
				})
			});

		let auth_headers_provider = HeadersProvider::new(Some("123".to_owned()));
		let entity_client = EntityClient::new(
			Arc::new(rest_client),
			Arc::new(JsonSerializer::new(type_model_provider.clone())),
			"http://test.com".to_owned(),
			Arc::new(auth_headers_provider),
			type_model_provider.clone(),
		);

		let result_entity = entity_client
			.load_range(
				&TestListCustomElementIdEntity::type_ref(),
				&list_id,
				&CustomId("zzzzzzzzzzzz".to_owned()),
				100,
				ListLoadDirection::DESC,
			)
			.await
			.expect("success");
		assert_eq!(result_entity, vec![entity_map]);
	}

	#[tokio::test]
	async fn test_load_range_asc_generated_element_id() {
		let type_model_provider = Arc::new(mock_type_model_provider());
		let id_field_id = type_model_provider
			.resolve_server_type_ref(&TestListGeneratedElementIdEntity::type_ref())
			.expect("list type not found")
			.get_attribute_id_by_attribute_name(ID_FIELD)
			.unwrap();
		let field_field_id = type_model_provider
			.resolve_server_type_ref(&TestListGeneratedElementIdEntity::type_ref())
			.expect("element type not found")
			.get_attribute_id_by_attribute_name("field")
			.unwrap();
		let list_id = GeneratedId("list_id".to_owned());
		let entity_map: ParsedEntity = collection! {
			id_field_id => ElementValue::IdTupleGeneratedElementId(IdTupleGenerated::new(list_id.clone(), GeneratedId("element_id".to_owned()))),
			field_field_id => ElementValue::Bytes(vec![1, 2, 3])
		};
		let mut rest_client = MockRestClient::new();
		let url = "http://test.com/rest/entityclienttestapp/TestListGeneratedElementIdEntity/list_id?start=------------&count=100&reverse=false";
		let json_folder = JsonSerializer::new(type_model_provider.clone())
			.serialize(
				&TestListGeneratedElementIdEntity::type_ref(),
				entity_map.clone(),
			)
			.unwrap();
		rest_client
			.expect_request_binary()
			.with(eq(url.to_owned()), eq(HttpMethod::GET), always())
			.return_once(move |_, _, _| {
				Ok(RestResponse {
					status: 200,
					headers: server_types_hash_header(),
					body: Some(serde_json::to_vec(&vec![json_folder]).unwrap()),
				})
			});

		let auth_headers_provider = HeadersProvider::new(Some("123".to_owned()));
		let entity_client = EntityClient::new(
			Arc::new(rest_client),
			Arc::new(JsonSerializer::new(type_model_provider.clone())),
			"http://test.com".to_owned(),
			Arc::new(auth_headers_provider),
			type_model_provider.clone(),
		);

		let result_entity = entity_client
			.load_range(
				&TestListGeneratedElementIdEntity::type_ref(),
				&list_id,
				&GeneratedId::min_id(),
				100,
				ListLoadDirection::ASC,
			)
			.await
			.expect("success");
		assert_eq!(result_entity, vec![entity_map]);
	}

	#[tokio::test]
	async fn test_load_range_asc_custom_element_id() {
		let type_model_provider = Arc::new(mock_type_model_provider());

		let list_id = GeneratedId("list_id".to_owned());
		let id_field_id = type_model_provider
			.resolve_server_type_ref(&TestListCustomElementIdEntity::type_ref())
			.expect("list type not found")
			.get_attribute_id_by_attribute_name(ID_FIELD)
			.unwrap();
		let field_field_id = type_model_provider
			.resolve_server_type_ref(&TestListCustomElementIdEntity::type_ref())
			.expect("custom id type not found")
			.get_attribute_id_by_attribute_name("field")
			.unwrap();
		let entity_map: ParsedEntity = collection! {
			id_field_id => ElementValue::IdTupleCustomElementId(IdTupleCustom::new(list_id.clone(), CustomId("element_id".to_owned()))),
			field_field_id => ElementValue::Bytes(vec![1, 2, 3])
		};
		let mut rest_client = MockRestClient::new();
		let url = "http://test.com/rest/entityclienttestapp/TestListCustomElementIdEntity/list_id?start=------------&count=100&reverse=false";
		let json_folder = JsonSerializer::new(type_model_provider.clone())
			.serialize(
				&TestListCustomElementIdEntity::type_ref(),
				entity_map.clone(),
			)
			.unwrap();
		rest_client
			.expect_request_binary()
			.with(eq(url.to_owned()), eq(HttpMethod::GET), always())
			.return_once(move |_, _, _| {
				Ok(RestResponse {
					status: 200,
					headers: server_types_hash_header(),
					body: Some(serde_json::to_vec(&vec![json_folder]).unwrap()),
				})
			});

		let auth_headers_provider = HeadersProvider::new(Some("123".to_owned()));
		let entity_client = EntityClient::new(
			Arc::new(rest_client),
			Arc::new(JsonSerializer::new(type_model_provider.clone())),
			"http://test.com".to_owned(),
			Arc::new(auth_headers_provider),
			type_model_provider.clone(),
		);

		let result_entity = entity_client
			.load_range(
				&TestListCustomElementIdEntity::type_ref(),
				&list_id,
				&CustomId("------------".to_owned()),
				100,
				ListLoadDirection::ASC,
			)
			.await
			.expect("success");
		assert_eq!(result_entity, vec![entity_map]);
	}

	#[tokio::test]
	async fn test_load_all_list_entries_asc() {
		let type_model_provider = Arc::new(mock_type_model_provider());

		let list_id = GeneratedId("list_id".to_owned());
		let id_field_id = type_model_provider
			.resolve_server_type_ref(&TestListCustomElementIdEntity::type_ref())
			.expect("list type not found")
			.get_attribute_id_by_attribute_name(ID_FIELD)
			.unwrap();
		let field_field_id = type_model_provider
			.resolve_server_type_ref(&TestListCustomElementIdEntity::type_ref())
			.expect("custom id type not found")
			.get_attribute_id_by_attribute_name("field")
			.unwrap();

		let entity_1: ParsedEntity = collection! {
			 id_field_id => ElementValue::IdTupleCustomElementId(IdTupleCustom::new(list_id.clone(), CustomId("element_id".to_owned()))),
			 field_field_id => ElementValue::Bytes(vec![1, 2, 3])
		};

		let entity_2: ParsedEntity = collection! {
			 id_field_id => ElementValue::IdTupleCustomElementId(IdTupleCustom::new(list_id.clone(), CustomId("element_id_1".to_owned()))),
			 field_field_id => ElementValue::Bytes(vec![1, 2, 3])
		};

		let mut rest_client = MockRestClient::new();
		let url1 = "http://test.com/rest/entityclienttestapp/TestListCustomElementIdEntity/list_id?start=------------&count=1000&reverse=false";
		let url2 = "http://test.com/rest/entityclienttestapp/TestListCustomElementIdEntity/list_id?start=element_id&count=1000&reverse=false";
		let url3 = "http://test.com/rest/entityclienttestapp/TestListCustomElementIdEntity/list_id?start=element_id_1&count=1000&reverse=false";

		let serialized_entity_1 = JsonSerializer::new(type_model_provider.clone())
			.serialize(&TestListCustomElementIdEntity::type_ref(), entity_1.clone())
			.unwrap();

		let serialized_entity_2 = JsonSerializer::new(type_model_provider.clone())
			.serialize(&TestListCustomElementIdEntity::type_ref(), entity_2.clone())
			.unwrap();

		rest_client
			.expect_request_binary()
			.with(eq(url1.to_owned()), eq(HttpMethod::GET), always())
			.return_once(move |_, _, _| {
				Ok(RestResponse {
					status: 200,
					headers: server_types_hash_header(),
					body: Some(serde_json::to_vec(&vec![serialized_entity_1]).unwrap()),
				})
			});

		rest_client
			.expect_request_binary()
			.with(eq(url2.to_owned()), eq(HttpMethod::GET), always())
			.return_once(move |_, _, _| {
				Ok(RestResponse {
					status: 200,
					headers: server_types_hash_header(),
					body: Some(serde_json::to_vec(&vec![serialized_entity_2]).unwrap()),
				})
			});

		let empty_list: Vec<ParsedEntity> = vec![];
		rest_client
			.expect_request_binary()
			.with(eq(url3.to_owned()), eq(HttpMethod::GET), always())
			.return_once(move |_, _, _| {
				Ok(RestResponse {
					status: 200,
					headers: server_types_hash_header(),
					body: Some(serde_json::to_vec(&empty_list).unwrap()),
				})
			});

		let auth_headers_provider = HeadersProvider::new(Some("123".to_owned()));
		let entity_client = EntityClient::new(
			Arc::new(rest_client),
			Arc::new(JsonSerializer::new(type_model_provider.clone())),
			"http://test.com".to_owned(),
			Arc::new(auth_headers_provider),
			type_model_provider.clone(),
		);

		let result_entities = entity_client
			.load_all(
				&TestListCustomElementIdEntity::type_ref(),
				&list_id,
				ListLoadDirection::ASC,
			)
			.await
			.expect("success");
		assert_eq!(result_entities, vec![entity_1, entity_2]);
	}

	#[tokio::test]
	async fn test_load_all_list_entries_desc() {
		let type_model_provider = Arc::new(mock_type_model_provider());

		let list_id = GeneratedId("list_id".to_owned());
		let id_field_id = type_model_provider
			.resolve_server_type_ref(&TestListCustomElementIdEntity::type_ref())
			.expect("list type not found")
			.get_attribute_id_by_attribute_name(ID_FIELD)
			.unwrap();
		let field_field_id = type_model_provider
			.resolve_server_type_ref(&TestListCustomElementIdEntity::type_ref())
			.expect("custom id type not found")
			.get_attribute_id_by_attribute_name("field")
			.unwrap();

		let entity_1: ParsedEntity = collection! {
			 id_field_id => ElementValue::IdTupleCustomElementId(IdTupleCustom::new(list_id.clone(), CustomId("element_id".to_owned()))),
			 field_field_id => ElementValue::Bytes(vec![1, 2, 3])
		};

		let entity_2: ParsedEntity = collection! {
			 id_field_id => ElementValue::IdTupleCustomElementId(IdTupleCustom::new(list_id.clone(), CustomId("element_id_1".to_owned()))),
			 field_field_id => ElementValue::Bytes(vec![1, 2, 3])
		};

		let mut rest_client = MockRestClient::new();
		let url1 = "http://test.com/rest/entityclienttestapp/TestListCustomElementIdEntity/list_id?start=zzzzzzzzzzzz&count=1000&reverse=true";
		let url2 = "http://test.com/rest/entityclienttestapp/TestListCustomElementIdEntity/list_id?start=element_id_1&count=1000&reverse=true";
		let url3 = "http://test.com/rest/entityclienttestapp/TestListCustomElementIdEntity/list_id?start=element_id&count=1000&reverse=true";

		let serialized_entity_1 = JsonSerializer::new(type_model_provider.clone())
			.serialize(&TestListCustomElementIdEntity::type_ref(), entity_1.clone())
			.unwrap();

		let serialized_entity_2 = JsonSerializer::new(type_model_provider.clone())
			.serialize(&TestListCustomElementIdEntity::type_ref(), entity_2.clone())
			.unwrap();

		rest_client
			.expect_request_binary()
			.with(eq(url1.to_owned()), eq(HttpMethod::GET), always())
			.return_once(move |_, _, _| {
				Ok(RestResponse {
					status: 200,
					headers: server_types_hash_header(),
					body: Some(serde_json::to_vec(&vec![serialized_entity_2]).unwrap()),
				})
			});

		rest_client
			.expect_request_binary()
			.with(eq(url2.to_owned()), eq(HttpMethod::GET), always())
			.return_once(move |_, _, _| {
				Ok(RestResponse {
					status: 200,
					headers: server_types_hash_header(),
					body: Some(serde_json::to_vec(&vec![serialized_entity_1]).unwrap()),
				})
			});

		let empty_list: Vec<ParsedEntity> = vec![];
		rest_client
			.expect_request_binary()
			.with(eq(url3.to_owned()), eq(HttpMethod::GET), always())
			.return_once(move |_, _, _| {
				Ok(RestResponse {
					status: 200,
					headers: server_types_hash_header(),
					body: Some(serde_json::to_vec(&empty_list).unwrap()),
				})
			});

		let auth_headers_provider = HeadersProvider::new(Some("123".to_owned()));
		let entity_client = EntityClient::new(
			Arc::new(rest_client),
			Arc::new(JsonSerializer::new(type_model_provider.clone())),
			"http://test.com".to_owned(),
			Arc::new(auth_headers_provider),
			type_model_provider.clone(),
		);

		let result_entities = entity_client
			.load_all(
				&TestListCustomElementIdEntity::type_ref(),
				&list_id,
				ListLoadDirection::DESC,
			)
			.await
			.expect("success");
		assert_eq!(result_entities, vec![entity_2, entity_1]);
	}
}
