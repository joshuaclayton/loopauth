use super::{Audience, Claims, Email, PictureUrl, SubjectIdentifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

impl Serialize for Claims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("OidcClaims", 9)?;
        s.serialize_field("sub", &self.sub)?;
        s.serialize_field("email", &self.email.as_ref().map(Email::as_str))?;
        s.serialize_field(
            "email_verified",
            &self.email.as_ref().map(Email::is_verified),
        )?;
        s.serialize_field("name", &self.name)?;
        s.serialize_field(
            "picture",
            &self.picture.as_ref().map(|p| p.as_url().as_str()),
        )?;
        s.serialize_field("iss", &self.iss)?;
        s.serialize_field("aud", &self.aud)?;
        let iat_secs = self
            .iat
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let exp_secs = self
            .exp
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        s.serialize_field("iat", &iat_secs)?;
        s.serialize_field("exp", &exp_secs)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for Claims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            sub: SubjectIdentifier,
            #[serde(default)]
            email: Option<String>,
            #[serde(default)]
            email_verified: Option<bool>,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            picture: Option<String>,
            iss: super::Issuer,
            #[serde(default, deserialize_with = "deserialize_aud")]
            aud: Vec<Audience>,
            #[serde(deserialize_with = "deserialize_system_time")]
            iat: SystemTime,
            #[serde(deserialize_with = "deserialize_system_time")]
            exp: SystemTime,
        }

        let h = Helper::deserialize(deserializer)?;
        Ok(Self {
            sub: h.sub,
            email: h.email.map(|e| Email::from_parts(e, h.email_verified)),
            name: h.name,
            picture: h.picture.and_then(|s| PictureUrl::parse(&s)),
            iss: h.iss,
            aud: h.aud,
            iat: h.iat,
            exp: h.exp,
        })
    }
}

fn deserialize_system_time<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
where
    D: Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    Ok(UNIX_EPOCH + Duration::from_secs(secs))
}

fn deserialize_aud<'de, D>(deserializer: D) -> Result<Vec<Audience>, D::Error>
where
    D: Deserializer<'de>,
{
    use crate::oidc::string_or_vec::StringOrVec;

    let opt = Option::<StringOrVec>::deserialize(deserializer)?;
    Ok(match opt {
        None => Vec::new(),
        Some(StringOrVec::Single(s)) => vec![Audience::new(s)],
        Some(StringOrVec::Multiple(v)) => v.into_iter().map(Audience::new).collect(),
    })
}
