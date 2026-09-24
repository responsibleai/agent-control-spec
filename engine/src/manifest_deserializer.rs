//! Keep numeric and boolean targets strict without discarding YAML locations
//! or letting Serde's JSON-value adapter deserialize structs positionally.
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use std::fmt;

pub(crate) struct Strict<D>(pub D);

macro_rules! forward {
    ($($method:ident $(($($arg:ident: $ty:ty),*))?;)*) => {$(
        fn $method<V: Visitor<'de>>(self, $($($arg: $ty,)*)? visitor: V)
            -> Result<V::Value, Self::Error>
        {
            self.0.$method($($($arg,)*)? Wrapped(visitor))
        }
    )*};
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Strict<D> {
    type Error = D::Error;

    // The parser's typed numeric methods accept quoted strings. Inference
    // instead hands the original scalar type to Serde's strict visitor.
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64
    }
    forward! {
        deserialize_any;
        deserialize_char;
        deserialize_str;
        deserialize_string;
        deserialize_bytes;
        deserialize_byte_buf;
        deserialize_option;
        deserialize_unit;
        deserialize_unit_struct(name: &'static str);
        deserialize_newtype_struct(name: &'static str);
        deserialize_seq;
        deserialize_tuple(len: usize);
        deserialize_tuple_struct(name: &'static str, len: usize);
        deserialize_map;
        deserialize_struct(name: &'static str, fields: &'static [&'static str]);
        deserialize_enum(name: &'static str, variants: &'static [&'static str]);
        deserialize_identifier;
        deserialize_ignored_any;
    }
}

struct Wrapped<V>(V);

macro_rules! scalar {
    ($($method:ident($ty:ty);)*) => {$(
        fn $method<E: de::Error>(self, value: $ty) -> Result<Self::Value, E> {
            self.0.$method(value)
        }
    )*};
}

impl<'de, V: Visitor<'de>> Visitor<'de> for Wrapped<V> {
    type Value = V::Value;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.expecting(formatter)
    }
    scalar! {
        visit_bool(bool);
        visit_i64(i64);
        visit_i128(i128);
        visit_u64(u64);
        visit_u128(u128);
        visit_f64(f64);
        visit_char(char);
        visit_str(&str);
        visit_borrowed_str(&'de str);
        visit_string(String);
        visit_bytes(&[u8]);
        visit_borrowed_bytes(&'de [u8]);
        visit_byte_buf(Vec<u8>);
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        self.0.visit_unit()
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.0.visit_none()
    }
    fn visit_some<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        self.0.visit_some(Strict(de))
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        self.0.visit_newtype_struct(Strict(de))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.0.visit_seq(Strict(access))
    }
    fn visit_map<A: MapAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.0.visit_map(Strict(access))
    }
    fn visit_enum<A: de::EnumAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.0.visit_enum(Strict(access))
    }
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Strict<S> {
    type Value = S::Value;
    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        self.0.deserialize(Strict(de))
    }
}

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Strict<A> {
    type Error = A::Error;
    fn next_element_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, Self::Error> {
        self.0.next_element_seed(Strict(seed))
    }
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for Strict<A> {
    type Error = A::Error;
    fn next_key_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, Self::Error> {
        self.0.next_key_seed(Strict(seed))
    }
    fn next_value_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<S::Value, Self::Error> {
        self.0.next_value_seed(Strict(seed))
    }
}

impl<'de, A: de::EnumAccess<'de>> de::EnumAccess<'de> for Strict<A> {
    type Error = A::Error;
    type Variant = Strict<A::Variant>;
    fn variant_seed<S: DeserializeSeed<'de>>(
        self,
        seed: S,
    ) -> Result<(S::Value, Self::Variant), Self::Error> {
        self.0
            .variant_seed(Strict(seed))
            .map(|(v, a)| (v, Strict(a)))
    }
}

impl<'de, A: de::VariantAccess<'de>> de::VariantAccess<'de> for Strict<A> {
    type Error = A::Error;
    fn unit_variant(self) -> Result<(), Self::Error> {
        self.0.unit_variant()
    }
    fn newtype_variant_seed<S: DeserializeSeed<'de>>(
        self,
        seed: S,
    ) -> Result<S::Value, Self::Error> {
        self.0.newtype_variant_seed(Strict(seed))
    }
    fn tuple_variant<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.0.tuple_variant(len, Wrapped(visitor))
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.0.struct_variant(fields, Wrapped(visitor))
    }
}
