//! Traits for serializing request payloads and deserializing responses in the client.

use coap_lite::{
    option_value::OptionValueU16, CoapOption, CoapRequest, CoapResponse, ContentFormat,
};
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::SocketAddr;

/// Trait for generating request payloads.
///
/// Types that implement `IntoPayload` can be sent as the payload of a client request.
pub trait IntoPayload {
    /// The content format of the payload, if any.
    fn content_format(&self) -> Option<ContentFormat> {
        None
    }

    /// Create a payload.
    fn into_payload(self) -> IoResult<Vec<u8>>;
}

/// Trait for extracting data from a response.
///
/// Types that implement `FromResponse` can be returned from typed client requests.
pub trait FromResponse: Sized {
    /// The content format to accept, if any.
    fn accept() -> Option<ContentFormat> {
        None
    }

    /// Extracts data from the given response, returning either the extracted value or an error.
    fn from_response(response: CoapResponse) -> IoResult<Self>;
}

/// Sets the Accept option of the request if `R` expects a content format.
pub(crate) fn set_accept<R: FromResponse>(request: &mut CoapRequest<SocketAddr>) {
    if let Some(accept) = R::accept() {
        let accept = u16::try_from(usize::from(accept)).unwrap();
        request
            .message
            .add_option_as(CoapOption::Accept, OptionValueU16(accept));
    }
}

/// Returns an error if the response has an error status code.
pub fn error_for_status(response: &CoapResponse) -> IoResult<()> {
    let status = response.get_status();
    if status.is_error() {
        return Err(Error::other(format!(
            "server responded with {:?}: {}",
            status,
            String::from_utf8_lossy(&response.message.payload)
        )));
    }
    Ok(())
}

impl IntoPayload for () {
    fn into_payload(self) -> IoResult<Vec<u8>> {
        Ok(Vec::new())
    }
}

impl IntoPayload for Vec<u8> {
    fn into_payload(self) -> IoResult<Vec<u8>> {
        Ok(self)
    }
}

impl IntoPayload for &[u8] {
    fn into_payload(self) -> IoResult<Vec<u8>> {
        Ok(self.to_vec())
    }
}

impl<const N: usize> IntoPayload for [u8; N] {
    fn into_payload(self) -> IoResult<Vec<u8>> {
        Ok(self.to_vec())
    }
}

impl<const N: usize> IntoPayload for &[u8; N] {
    fn into_payload(self) -> IoResult<Vec<u8>> {
        Ok(self.to_vec())
    }
}

impl IntoPayload for String {
    fn content_format(&self) -> Option<ContentFormat> {
        Some(ContentFormat::TextPlain)
    }

    fn into_payload(self) -> IoResult<Vec<u8>> {
        Ok(self.into_bytes())
    }
}

impl IntoPayload for &str {
    fn content_format(&self) -> Option<ContentFormat> {
        Some(ContentFormat::TextPlain)
    }

    fn into_payload(self) -> IoResult<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }
}

impl FromResponse for CoapResponse {
    fn from_response(response: CoapResponse) -> IoResult<Self> {
        Ok(response)
    }
}

impl FromResponse for () {
    fn from_response(response: CoapResponse) -> IoResult<Self> {
        error_for_status(&response)
    }
}

impl FromResponse for Vec<u8> {
    fn from_response(response: CoapResponse) -> IoResult<Self> {
        error_for_status(&response)?;
        Ok(response.message.payload)
    }
}

impl FromResponse for String {
    fn from_response(response: CoapResponse) -> IoResult<Self> {
        error_for_status(&response)?;
        String::from_utf8(response.message.payload)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::{Method, RequestBuilder};
    use coap_lite::{MessageClass, Packet, ResponseType};

    fn response(status: ResponseType, payload: &[u8]) -> CoapResponse {
        let mut message = Packet::new();
        message.header.code = MessageClass::Response(status);
        message.payload = payload.to_vec();
        CoapResponse { message }
    }

    #[test]
    fn test_body() {
        let request = RequestBuilder::new("/", Method::Post)
            .body("hello")
            .unwrap()
            .build();
        assert_eq!(request.message.payload, b"hello");
        assert_eq!(
            request.message.get_content_format(),
            Some(ContentFormat::TextPlain)
        );

        let request = RequestBuilder::new("/", Method::Post)
            .body(vec![1, 2, 3])
            .unwrap()
            .build();
        assert_eq!(request.message.payload, vec![1, 2, 3]);
        assert_eq!(request.message.get_content_format(), None);
    }

    #[test]
    fn test_set_accept() {
        let mut request = CoapRequest::new();
        set_accept::<String>(&mut request);
        assert!(request.message.get_option(CoapOption::Accept).is_none());
    }

    #[test]
    fn test_from_response() {
        let ok = response(ResponseType::Content, b"hello");
        assert_eq!(String::from_response(ok.clone()).unwrap(), "hello");
        assert_eq!(Vec::<u8>::from_response(ok).unwrap(), b"hello");

        let err = response(ResponseType::NotFound, b"Not found");
        assert!(String::from_response(err.clone()).is_err());
        assert!(<()>::from_response(err.clone()).is_err());
        // The raw response is always returned, regardless of status.
        assert!(CoapResponse::from_response(err).is_ok());
    }
}
