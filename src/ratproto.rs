use std::{fmt, str::FromStr};

use color_eyre::eyre::eyre;
use hickory_resolver::Resolver;
use serde::Deserialize;

#[derive(thiserror::Error, Debug)]
pub enum HandleError {
    #[error("HANDLE: \"{0}\" is not ASCII")]
    NotAscii(Box<str>),
    #[error("HANDLE: \"{0}\" is more than {1} characters long")]
    HandleTooLong(Box<str>, usize),
    #[error("HANDLE: \"{0}\" must contain atleast two segments separated by a .")]
    HandleIsTLD(Box<str>),
    #[error("TLD SEGMENT: \"{0}\" starts with a digit")]
    TLDStartsWithDigit(Box<str>),
    #[error("INVALID SYNTAX: Proceeding or trailing periods ('.') are not allowed")]
    InvalidPeriods,
    #[error("SEGMENT: \"{0}\" is more than {1} characters long")]
    SegmentTooLong(Box<str>, usize),
    #[error("SEGMENT: \"{0}\" contains Illegal Characters")]
    SegmentIllegalChar(Box<str>),
    #[error("SEGMENT: \"{0}\" can not start or end with a hyphen")]
    SegmentHyphensAtEdges(Box<str>),

    #[error(transparent)]
    Source(#[from] color_eyre::Report),
}

#[derive(thiserror::Error, Debug)]
pub enum DidError {
    #[error("DID: \"{0}\" contains illegal characters")]
    IllegalChars(Box<str>),
    #[error("DID: \"{0}\" has missing segments")]
    Incomplete(Box<str>),
    #[error("SCHEME: \"{0}\" is not valid for DID")]
    InvalidScheme(Box<str>),
    #[error("METHOD: \"{0}\" is not supported for ATProto")]
    UnsupportedMethod(Box<str>),
    #[error("INVALID SYNTAX: Proceeding or trailing colons (':') are not allowed")]
    InvalidColons,
    #[error("IDENTIFIER: \"{0}\" contains an invalid character")]
    InvalidCharInIdentifier(Box<str>),

    #[error(transparent)]
    Source(#[from] color_eyre::Report),
}

#[derive(Debug, PartialEq, Eq)]
pub enum DidMethod {
    Plc,
    Web,
}

#[derive(Debug)]
pub struct Did(Box<str>, DidMethod);

impl Did {
    pub async fn resolve(&self) -> color_eyre::Result<DidDocument> {
        if self.is_plc() {
            self.resolve_plc().await
        } else if self.is_web() {
            self.resolve_web().await
        } else {
            Err(eyre!("No DID Document Found"))
        }
    }

    async fn resolve_plc(&self) -> color_eyre::Result<DidDocument> {
        let url = format!("https://plc.directory/{self}");
        let body = reqwest::get(url).await?.text().await?;

        let doc: DidDocument = serde_json::from_str(&body)?;
        println!("{doc:#?}");
        Ok(doc)
    }

    async fn resolve_web(&self) -> color_eyre::Result<DidDocument> {
        let identifier = self.get_identifier();
        let url = format!("https://{identifier}/.well-known/did.json");
        let body = reqwest::get(url).await?.text().await?;

        let doc: DidDocument = serde_json::from_str(&body)?;
        println!("{doc:#?}");
        Ok(doc)
    }
    fn is_plc(&self) -> bool {
        if self.1 == DidMethod::Plc {
            return true;
        }
        false
    }

    fn is_web(&self) -> bool {
        if self.1 == DidMethod::Web {
            return true;
        }
        false
    }

    fn get_identifier(&self) -> Box<str> {
        let segments: Vec<Box<str>> = self.0.split(':').map(Box::from).collect();
        segments[2].clone()
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Did {
    type Err = DidError;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        // When resolving a handle with DNS the entry should start with did=
        // We can just trim it here.
        if s.contains("did=") {
            s = &s[4..];
        }

        // The entire URI is made up of a subste of ASCII, containing
        // letters ('A-z', 'a-z')
        // digits  ('0,9')
        // and period, underscore, colon, percent sign, and hyphen.
        // ('._:%-')
        if !s.chars().all(|c| match c {
            c if c.is_ascii_alphanumeric() => true,
            '.' | '_' | ':' | '%' | '-' => true,
            _ => false,
        }) {
            return Err(DidError::IllegalChars(s.into()));
        }

        // DIDs are split into 3 segments separated by a colon.
        let segments: Vec<Box<str>> = s.split(':').map(Box::from).collect();

        // DIDs most contain atleast 3 segments, some methods may have
        // more complex identifiers.
        if segments.len() < 3 {
            return Err(DidError::Incomplete(s.into()));
        }

        // DIDs cannot end in colons (':'). This also catches some invalid
        // syntaxes
        for segment in &segments {
            if segment.is_empty() {
                return Err(DidError::InvalidColons);
            }
        }

        let scheme = segments[0].to_lowercase();
        let method = segments[1].to_lowercase();
        let identifier = &segments[2];

        // DIDs must begin with the "did" scheme.
        if scheme != "did" {
            return Err(DidError::InvalidScheme(scheme.into()));
        }

        let method_enum: DidMethod;
        // PLC has a few different requirements than WEB
        if method == "plc" {
            method_enum = DidMethod::Plc;
            // % is not allowed in plc identifiers
            if identifier.chars().all(|c| c == '%') {
                return Err(DidError::InvalidCharInIdentifier(identifier.clone()));
            }
        } else if method == "web" {
            method_enum = DidMethod::Web;
            // % must be followed by 2 hex characters. I don't need to validate
            // these as invalid percent encoding should fail any attempts
            // at resolution, registration, etc.
            if identifier.chars().last() == Some('%') || identifier.chars().nth_back(1) == Some('&')
            {
                return Err(DidError::InvalidCharInIdentifier(identifier.clone()));
            }
        } else {
            return Err(DidError::UnsupportedMethod(method.into()));
        }

        let did = Box::from(format!("{scheme}:{method}:{identifier}"));
        Ok(Did(did, method_enum))
    }
}

const HANDLE_LEN: usize = 253;
const SEGMENT_LEN: usize = 63;

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct Handle(Box<str>);

impl Handle {
    pub async fn resolve(&self) -> color_eyre::Result<Did> {
        let dns_res = self.resolve_dns().await;
        let well_known_res = self.resolve_well_known().await;

        if dns_res.is_ok() && well_known_res.is_err() {
            return dns_res;
        }

        if dns_res.is_err() && well_known_res.is_ok() {
            return well_known_res;
        }

        if dns_res.is_ok() && well_known_res.is_ok() {
            return dns_res;
        }

        Err(eyre!("No DID found"))
    }

    async fn resolve_dns(&self) -> color_eyre::Result<Did> {
        let txt = format!("_atproto.{}.", self);
        let resolver = Resolver::builder_tokio().unwrap().build();
        let response = resolver.txt_lookup(txt).await;

        match response {
            Err(_) => return Err(eyre!("No DID found")),
            _ => (),
        }

        let response = response.unwrap();
        let records = response.iter();
        for record in records {
            let did: Result<Did, DidError> = Did::from_str(&record.to_string());
            match did {
                Ok(did) => return Ok(did),
                Err(err) => eprintln!("{err}"),
            }
        }

        Err(eyre!("No DID found"))
    }

    async fn resolve_well_known(&self) -> color_eyre::Result<Did> {
        let url = format!("https://{self}/.well-known/atproto-did");
        let body = reqwest::get(url).await?.text().await?;

        let did = Did::from_str(&body);
        if let Ok(did) = did {
            return Ok(did);
        }
        Err(eyre!("No DID found"))
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}

impl FromStr for Handle {
    type Err = HandleError;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        // ATProto Handles have defined syntax requirements
        // Instead of validating handles after, I simply only allow valid
        // Handles to be made.

        // The handle must contain only ASCII characters.
        if !s.is_ascii() {
            return Err(HandleError::NotAscii(s.into()));
        };

        // The handle can be at most 253 characters long,
        // This requirement can definetly be shortened.
        if s.len() > HANDLE_LEN {
            return Err(HandleError::HandleTooLong(s.into(), HANDLE_LEN));
        };

        // Handles may be prefixed with the "@" symbol in user interfaces
        // but this is not valid syntax in the backend. So the prefixed @
        // character is simply removed. Any other @ characters will be caught
        // as an error.
        if s.chars().next().unwrap() == '@' {
            s = &s[1..];
        };
        
        // Handles may also be prefixed with "at://" as part of ATProto.
        if s[0..5].contains("at://") {
            s = &s[5..];
        }

        // The Handle is split into multiple segments, these are referred to as
        // labels, and are separated by ASCII periods.
        let segments: Vec<Box<str>> = s.split('.').map(Box::from).collect();

        // A handle must have atleast 2 segments, as TLDs on their own are not
        // allowed.
        if segments.len() < 2 {
            return Err(HandleError::HandleIsTLD(s.into()));
        }

        // The last segment (TLD) may not start with a numeric digit.
        if segments
            .last()
            .unwrap()
            .starts_with(|c: char| c.is_ascii_digit())
        {
            return Err(HandleError::TLDStartsWithDigit(
                segments.last().unwrap().clone(),
            ));
        }

        for segment in segments {
            // The presence of an empty segment, signifies a couple of broken
            // syntax rules.
            // Proceeding or trailing ASCII periods are not allowed.
            // Each segment must have atleast 1 character. so (dog..tld) is not
            // allowed.
            if segment.is_empty() {
                return Err(HandleError::InvalidPeriods);
            }

            // Each segment can be at most 63 characters in length.
            // Not including periods.
            if segment.len() >= SEGMENT_LEN {
                return Err(HandleError::SegmentTooLong(segment, SEGMENT_LEN));
            }

            // The allowed characters in a segment are:
            // ASCII letters ('a-z')
            // ASCII digits  ('0-9')
            // ASCII hyphens ('-')
            if !segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                return Err(HandleError::SegmentIllegalChar(segment));
            }

            // Segments may not start or end with a hyphen.
            if segment.starts_with('-') || segment.ends_with('-') {
                return Err(HandleError::SegmentHyphensAtEdges(segment));
            }
        }

        // Handles are not case-sensitive and are normalized to lowercase.
        let handle = Box::from(s.to_ascii_lowercase());
        Ok(Handle(handle))
    }
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    context: Vec<Box<str>>,
    #[serde(rename = "alsoKnownAs")]
    also_known_as: Vec<Box<str>>,
    id: Box<str>,
    service: Vec<DidService>,
    #[serde(rename = "verificationMethod")]
    verification_method: Vec<DidVerificationMethod>,
}

impl DidDocument {
    pub fn match_handle(&self, handle: Handle) -> bool {
        let aka = Handle::from_str(&self.also_known_as[0]).unwrap();
        if aka == handle {
            return true;
        }

        false
    }
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct DidService {
    id: Box<str>,
    #[serde(rename = "serviceEndpoint")]
    service_endpoint: Box<str>,
    r#type: Box<str>,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct DidVerificationMethod {
    controller: Box<str>,
    id: Box<str>,
    #[serde(rename = "publicKeyMultibase")]
    public_key_multibase: Box<str>,
    r#type: Box<str>,
}

pub mod oauth {
    use std::collections::HashMap;

    use super::Handle;
    use color_eyre::eyre::Result;
    use libsql::Database;
    use oauth2::basic::BasicClient;

    enum AppType {
        Web,
        Native,
    }

    enum GrantType {
        AuthorizationCode,
        RefreshToken,
    }

    struct Jwks {
        keys: Vec<HashMap<Box<str>, Box<str>>>,
    }

    struct ATProtoClientMeta {
        client_id: Box<str>,
        application_type: Option<AppType>,
        grant_types: Vec<GrantType>,
        scope: Box<str>,
        response_types: Vec<Box<str>>,
        redirect_uris: Option<Vec<Box<str>>>,
        token_endpoint_auth_method: Option<Box<str>>,
        token_endpoint_auth_signing_alg: Option<Box<str>>,
        dpop_bound_access_tokens: bool,
        jwks: Option<Jwks>,
        jwks_uri: Option<Box<str>>,

        client_name: Option<Box<str>>,
        client_uri: Option<Box<str>>,
        logo_uri: Option<Box<str>>,
        tos_uri: Option<Box<str>>,
        policy_uri: Option<Box<str>>,
    }

    impl Default for ATProtoClientMeta {
        fn default() -> Self {
            ATProtoClientMeta {
                client_id: "http://localhost".into(),
                application_type: Some(AppType::Web),
                grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                scope: "atproto transition:generic".into(),
                response_types: vec!["code".into()],
                redirect_uris: Some(vec!["http://127.0.0.1/".into(), "http://[::1]/".into()]),
                token_endpoint_auth_method: None,
                token_endpoint_auth_signing_alg: None,
                dpop_bound_access_tokens: true,
                jwks: None,
                jwks_uri: None,
                client_name: Some("Wicket Statusphere RS".into()),
                client_uri: None,
                logo_uri: None,
                tos_uri: None,
                policy_uri: None,
            }
        }
    }

    type ATProtoOAuthClient = BasicClient;

    async fn create_client(_db: Database) -> Result<ATProtoOAuthClient> {
        todo!()
    }

    pub async fn authorize(handle: Handle) {
        handle.resolve();
        todo!()
    }
}
