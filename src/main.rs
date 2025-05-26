use redis::Commands;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;
use keyring;
use dirs::config_dir;

const APP_NAME: &str = "secretshared";
const REDIS_URL_KEY: &str = "redis_url";

fn get_config_path() -> PathBuf {
    let mut path = config_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push(APP_NAME);
    path
}

fn store_redis_url(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let keyring = keyring::Entry::new(APP_NAME, REDIS_URL_KEY)
        .map_err(|e| format!("Error al crear keyring: {}", e))?;
    keyring.set_password(url)
        .map_err(|e| format!("Error al almacenar URL: {}", e))?;
    Ok(())
}

fn get_redis_url() -> Result<String, Box<dyn std::error::Error>> {
    let keyring = keyring::Entry::new(APP_NAME, REDIS_URL_KEY)
        .map_err(|e| format!("Error al crear keyring: {}", e))?;
    let url = keyring.get_password()
        .map_err(|e| format!("Error al obtener URL: {}", e))?;
    Ok(url)
}

struct EncryptedData {
    key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl EncryptedData {
    fn to_string(&self) -> String {
        let mut combined = Vec::new();
        combined.extend_from_slice(&self.key);
        combined.extend_from_slice(&self.nonce);
        combined.extend_from_slice(&self.ciphertext);
        BASE64.encode(&combined)
    }

    fn from_string(encoded: &str) -> Result<Self, String> {
        let combined = BASE64.decode(encoded)
            .map_err(|e| format!("Error al decodificar base64: {}", e))?;
        
        if combined.len() < 44 { // 32 (key) + 12 (nonce)
            return Err("Datos encriptados inválidos".to_string());
        }

        let key = combined[0..32].to_vec();
        let nonce = combined[32..44].to_vec();
        let ciphertext = combined[44..].to_vec();

        Ok(EncryptedData {
            key,
            nonce,
            ciphertext,
        })
    }
}

fn encrypt_value(value: &str) -> Result<String, String> {
    // Generate a random key and nonce
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher.encrypt(nonce, value.as_bytes())
        .map_err(|e| format!("Error al encriptar: {}", e))?;
    
    let encrypted_data = EncryptedData {
        key: key_bytes.to_vec(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    };

    Ok(encrypted_data.to_string())
}

fn decrypt_value(encrypted: &str) -> Result<String, String> {
    let encrypted_data = EncryptedData::from_string(encrypted)?;
    
    let key = Key::<Aes256Gcm>::from_slice(&encrypted_data.key);
    let nonce = Nonce::from_slice(&encrypted_data.nonce);
    
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher.decrypt(nonce, encrypted_data.ciphertext.as_slice())
        .map_err(|e| format!("Error al desencriptar: {}", e))?;
    
    String::from_utf8(plaintext)
        .map_err(|e| format!("Error al convertir a UTF-8: {}", e))
}

fn ejecutar_comando(accion: &str, parametros: Vec<String>, con: Option<&mut redis::Connection>) -> Result<(), Box<dyn std::error::Error>> {
    match accion {
        "init" => {
            if parametros.len() != 1 {
                println!("Uso: init <url_redis>");
                return Ok(());
            }

            let url = &parametros[0];
            
            // Verificar que la URL es válida intentando conectar
            let client = redis::Client::open(url.as_str())?;
            let _con = client.get_connection()?;

            // Almacenar la URL de forma segura
            store_redis_url(url)?;
            println!("URL de Redis almacenada exitosamente");
        }
        "saludar" => {
            let nombre = parametros.get(0).cloned().unwrap_or_else(||"invitado".to_string());
            println!("Hola, {}!", nombre);
        }
        "create" => {
            if let Some(con) = con {
                if parametros.len() != 3 {
                    println!("Uso: create <nombre_del_grupo> <nombre_de_la_clave> <valor>");
                    return Ok(());
                }
                
                let grupo = &parametros[0];
                let clave = &parametros[1];
                let valor = &parametros[2];
                
                let encrypted_value = encrypt_value(valor)
                    .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
                let redis_key = format!("secret:{}:{}", grupo, clave);
                
                con.set(&redis_key, encrypted_value)?;
                println!("Secreto creado exitosamente");
            }
        }
        "get" => {
            if let Some(con) = con {
                if parametros.len() != 1 {
                    println!("Uso: get <nombre_del_grupo>");
                    return Ok(());
                }

                let grupo = &parametros[0];
                let pattern = format!("secret:{}:*", grupo);
                
                // Get all keys matching the pattern
                let keys: Vec<String> = con.keys(&pattern)?;
                
                if keys.is_empty() {
                    println!("No se encontraron claves para el grupo '{}'", grupo);
                    return Ok(());
                }

                println!("Claves encontradas en el grupo '{}':", grupo);
                for key in keys {
                    // Extract the key name from the full Redis key
                    if let Some(key_name) = key.split(':').last() {
                        // Get the encrypted value from Redis
                        let encrypted_value: String = con.get(&key)?;
                        match decrypt_value(&encrypted_value) {
                            Ok(decrypted_value) => {
                                println!("- {}: {}", key_name, decrypted_value);
                            }
                            Err(e) => {
                                println!("- {}: [Error al desencriptar: {}]", key_name, e);
                            }
                        }
                    }
                }
            }
        }
        "list" => {
            if let Some(con) = con {
                // Get all keys with the secret: prefix
                let pattern = "secret:*";
                let keys: Vec<String> = con.keys(pattern)?;
                
                if keys.is_empty() {
                    println!("No hay grupos disponibles");
                    return Ok(());
                }

                // Extract unique group names
                let mut grupos: std::collections::HashSet<String> = std::collections::HashSet::new();
                for key in keys {
                    if let Some(grupo) = key.split(':').nth(1) {
                        grupos.insert(grupo.to_string());
                    }
                }

                println!("Grupos disponibles:");
                for grupo in grupos {
                    println!("- {}", grupo);
                }
            }
        }
        "dump" => {
            if let Some(con) = con {
                if parametros.len() != 1 {
                    println!("Uso: dump <nombre_del_grupo>");
                    return Ok(());
                }

                let grupo = &parametros[0];
                let pattern = format!("secret:{}:*", grupo);
                
                // Get all keys matching the pattern
                let keys: Vec<String> = con.keys(&pattern)?;
                
                if keys.is_empty() {
                    println!("No se encontraron claves para el grupo '{}'", grupo);
                    return Ok(());
                }

                // Create .env file
                let filename = format!("{}.env", grupo);
                let mut file = File::create(&filename)
                    .map_err(|e| format!("Error al crear archivo: {}", e))?;

                // Write header
                writeln!(file, "# Archivo .env generado para el grupo '{}'", grupo)?;
                writeln!(file, "# Fecha de generación: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))?;
                writeln!(file)?;

                // Write each key-value pair
                for key in keys {
                    if let Some(key_name) = key.split(':').last() {
                        let encrypted_value: String = con.get(&key)?;
                        match decrypt_value(&encrypted_value) {
                            Ok(decrypted_value) => {
                                writeln!(file, "{}={}", key_name.to_uppercase(), decrypted_value)?;
                            }
                            Err(e) => {
                                writeln!(file, "# Error al desencriptar {}: {}", key_name, e)?;
                            }
                        }
                    }
                }

                println!("Archivo {}.env generado exitosamente", grupo);
            }
        }
        _ => {
            println!("Comando no válido");
        }
    }
    Ok(())
}

fn main() -> Res  ult<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let accion = args.next().unwrap_or("".to_string());
    let parametros: Vec<String> = args.collect();

    // Si no es el comando init, necesitamos la URL de Redis
    if accion != "init" {
        match get_redis_url() {
            Ok(redis_url) => {
                let client = redis::Client::open(redis_url.as_str())?;
                let mut con = client.get_connection()?;
                ejecutar_comando(&accion, parametros, Some(&mut con))?;
            }
            Err(_) => {
                println!("Error: Redis no está configurado.");
                println!("Por favor, ejecute el siguiente comando para configurar Redis:");
                println!("  init <url_redis>");
                println!("\nEjemplo:");
                println!("  init redis://usuario:contraseña@host:puerto");
            }
        }
    } else {
        // Para el comando init, no necesitamos conexión a Redis
        ejecutar_comando(&accion, parametros, None)?;
    }

    Ok(())
}
