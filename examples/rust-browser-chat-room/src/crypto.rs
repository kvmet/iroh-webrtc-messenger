use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, prelude::*};
use wasm_bindgen_futures::JsFuture;
use web_sys::TextEncoder;

async fn aes_key(
    passphrase: &str,
    salt: &[u8],
    usage: &str,
) -> std::result::Result<web_sys::CryptoKey, JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    let subtle = window.crypto()?.subtle();

    let pass_bytes = Uint8Array::from(TextEncoder::new()?.encode_with_input(passphrase).as_slice());
    let derive_usages = Array::of1(&JsValue::from_str("deriveKey"));
    let key_material: web_sys::CryptoKey = JsFuture::from(subtle.import_key_with_str(
        "raw",
        pass_bytes.unchecked_ref::<Object>(),
        "PBKDF2",
        false,
        &derive_usages,
    )?)
    .await?
    .dyn_into()?;

    let pbkdf2 = Object::new();
    Reflect::set(&pbkdf2, &"name".into(), &"PBKDF2".into())?;
    Reflect::set(&pbkdf2, &"salt".into(), &Uint8Array::from(salt))?;
    Reflect::set(&pbkdf2, &"iterations".into(), &JsValue::from(600_000u32))?;
    Reflect::set(&pbkdf2, &"hash".into(), &"SHA-256".into())?;

    let aes_spec = Object::new();
    Reflect::set(&aes_spec, &"name".into(), &"AES-GCM".into())?;
    Reflect::set(&aes_spec, &"length".into(), &JsValue::from(256u32))?;

    let key_usages = Array::of1(&JsValue::from_str(usage));
    JsFuture::from(subtle.derive_key_with_object_and_object(
        &pbkdf2,
        &key_material,
        &aes_spec,
        false,
        &key_usages,
    )?)
    .await?
    .dyn_into()
}

pub(crate) async fn encrypt_key(
    key_bytes: &[u8; 32],
    passphrase: &str,
) -> std::result::Result<(Vec<u8>, Vec<u8>), JsValue> {
    let crypto = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .crypto()?;

    let salt_arr = Uint8Array::new_with_length(16);
    crypto.get_random_values_with_array_buffer_view(&salt_arr)?;
    let salt = salt_arr.to_vec();

    let iv_arr = Uint8Array::new_with_length(12);
    crypto.get_random_values_with_array_buffer_view(&iv_arr)?;
    let iv = iv_arr.to_vec();

    let cipher_key = aes_key(passphrase, &salt, "encrypt").await?;
    let params = Object::new();
    Reflect::set(&params, &"name".into(), &"AES-GCM".into())?;
    Reflect::set(&params, &"iv".into(), &Uint8Array::from(iv.as_slice()))?;

    let subtle = crypto.subtle();
    let ct = JsFuture::from(subtle.encrypt_with_object_and_buffer_source(
        &params,
        &cipher_key,
        &Uint8Array::from(key_bytes.as_slice()),
    )?)
    .await?;

    let mut encrypted = iv;
    encrypted.extend_from_slice(&Uint8Array::new(&ct).to_vec());
    Ok((encrypted, salt))
}

pub(crate) async fn decrypt_key(
    encrypted: &[u8],
    salt: &[u8],
    passphrase: &str,
) -> std::result::Result<[u8; 32], JsValue> {
    if encrypted.len() < 13 {
        return Err(JsValue::from_str("ciphertext too short"));
    }
    let iv = &encrypted[..12];
    let ct = &encrypted[12..];

    let cipher_key = aes_key(passphrase, salt, "decrypt").await?;
    let params = Object::new();
    Reflect::set(&params, &"name".into(), &"AES-GCM".into())?;
    Reflect::set(&params, &"iv".into(), &Uint8Array::from(iv))?;

    let subtle = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .crypto()?
        .subtle();
    let pt = JsFuture::from(subtle.decrypt_with_object_and_buffer_source(
        &params,
        &cipher_key,
        &Uint8Array::from(ct),
    )?)
    .await?;

    Uint8Array::new(&pt)
        .to_vec()
        .try_into()
        .map_err(|_| JsValue::from_str("decrypted key has wrong length"))
}

async fn raw_aes_key(
    key_bytes: &[u8; 32],
    usage: &str,
) -> std::result::Result<web_sys::CryptoKey, JsValue> {
    let subtle = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .crypto()?
        .subtle();
    let arr = Uint8Array::from(key_bytes.as_slice());
    let usages = Array::of1(&JsValue::from_str(usage));
    JsFuture::from(subtle.import_key_with_str(
        "raw",
        arr.unchecked_ref::<Object>(),
        "AES-GCM",
        false,
        &usages,
    )?)
    .await?
    .dyn_into()
}

pub(crate) async fn encrypt_data(
    data: &[u8],
    key_bytes: &[u8; 32],
) -> std::result::Result<Vec<u8>, JsValue> {
    let crypto = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .crypto()?;
    let iv_arr = Uint8Array::new_with_length(12);
    crypto.get_random_values_with_array_buffer_view(&iv_arr)?;
    let iv = iv_arr.to_vec();
    let cipher_key = raw_aes_key(key_bytes, "encrypt").await?;
    let params = Object::new();
    Reflect::set(&params, &"name".into(), &"AES-GCM".into())?;
    Reflect::set(&params, &"iv".into(), &Uint8Array::from(iv.as_slice()))?;
    let subtle = crypto.subtle();
    let ct = JsFuture::from(subtle.encrypt_with_object_and_buffer_source(
        &params,
        &cipher_key,
        &Uint8Array::from(data),
    )?)
    .await?;
    let mut result = iv;
    result.extend_from_slice(&Uint8Array::new(&ct).to_vec());
    Ok(result)
}

pub(crate) async fn decrypt_data(
    encrypted: &[u8],
    key_bytes: &[u8; 32],
) -> std::result::Result<Vec<u8>, JsValue> {
    if encrypted.len() < 13 {
        return Err(JsValue::from_str("ciphertext too short"));
    }
    let iv = &encrypted[..12];
    let ct = &encrypted[12..];
    let cipher_key = raw_aes_key(key_bytes, "decrypt").await?;
    let params = Object::new();
    Reflect::set(&params, &"name".into(), &"AES-GCM".into())?;
    Reflect::set(&params, &"iv".into(), &Uint8Array::from(iv))?;
    let subtle = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .crypto()?
        .subtle();
    let pt = JsFuture::from(subtle.decrypt_with_object_and_buffer_source(
        &params,
        &cipher_key,
        &Uint8Array::from(ct),
    )?)
    .await?;
    Ok(Uint8Array::new(&pt).to_vec())
}
