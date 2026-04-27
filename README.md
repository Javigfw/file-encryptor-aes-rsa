# P4YM3PLZ 🔐

Herramienta realizada por grupo de investigación universitario de **cifrado híbrido AES + RSA** para archivos. Cifra cualquier archivo con AES (CBC/CFB/OFB/CTR) y protege la clave simétrica mediante cifrado asimétrico RSA con OAEP-SHA256. Los archivos cifrados se guardan con extensión `.p4ym3`. Hecho para el aprendizaje

---

## Características

- **Cifrado híbrido**: AES para los datos + RSA para la clave simétrica 
- **Modos AES**: CBC, CFB, OFB y CTR
- **Tamaños de clave AES**: 128, 192 o 256 bits
- **Claves RSA**: 2048 o 3072 bits con cifrado opcional por contraseña (PKCS8)
- **Key wrapping**: RSA-OAEP con SHA-256 y MGF1
- **Formato propio `.p4ym3`**: cabecera ASCII legible + clave envuelta en Base64 + datos binarios

---

## Requisitos

- Python 3.8+
- [`cryptography`](https://pypi.org/project/cryptography/)

```bash
pip install cryptography
```

---

## Uso

```bash
python P4YM3PLZ.py
```

El programa presenta un menú interactivo con tres opciones:

### [G] Generar par de claves RSA

Genera una clave privada y una clave pública RSA y las guarda como `rsa_private.pem` y `rsa_public.pem` en el directorio actual. La clave privada puede protegerse con contraseña.

```
Selecciona opción: G
Tamaño de clave RSA (2048/3072, por defecto 3072): 3072
Introduce una contraseña para cifrar la clave privada (o deja vacío): ****
```

### [C] Cifrar un archivo

Cifra cualquier archivo usando la clave pública del destinatario. Solo el poseedor de la clave privada correspondiente podrá descifrarlo.

```
Selecciona opción: C
Ruta del archivo de entrada: documento.pdf
Longitud de clave en bits: 256
Modo de cifrado (CBC/CFB/OFB/CTR): CTR
Ruta a la clave PÚBLICA RSA (PEM): rsa_public.pem
→ Archivo cifrado: documento.p4ym3
```

### [D] Descifrar un archivo

Descifra un archivo `.p4ym3` usando la clave privada. El modo AES y el tamaño de clave se leen automáticamente del encabezado.

```
Selecciona opción: D
Ruta del archivo de entrada: documento.p4ym3
Ruta a la clave PRIVADA RSA (PEM): rsa_private.pem
¿La clave privada tiene contraseña? (S/N): S
Introduce la contraseña: ****
→ Archivo descifrado: documento_dec.p4ym3
```

---

## Formato del archivo `.p4ym3`

```
Línea 1: P4Y1|<MODO>|<KEYBITS>|PKALG=RSA_OAEP_SHA256\n
Línea 2: <CLAVE_SIMÉTRICA_ENVUELTA_EN_BASE64>\n
Binario:  IV (16 bytes) + DATOS CIFRADOS
```

Ejemplo de cabecera:
```
P4Y1|CTR|256|PKALG=RSA_OAEP_SHA256
kT3f...base64...==
```

---

## Flujo de cifrado

```
Datos originales
      │
      ▼
  AES (modo elegido)  ◄──── Clave AES aleatoria
      │                            │
      ▼                            ▼
Datos cifrados             RSA-OAEP cifra la clave AES
      │                            │
      └──────────┬─────────────────┘
                 ▼
          archivo .p4ym3
```

---

## Estructura del proyecto

```
P4YM3PLZ.py          # Script principal 
rsa_private.pem      # Clave privada generada 
rsa_public.pem       # Clave pública generada
```

> ⚠️ **Nunca subas tu clave privada (`rsa_private.pem`) a un repositorio público.**  
> Añádela a `.gitignore`:
> ```
> rsa_private.pem
> ```

---

## Seguridad

| Componente | Detalle |
|---|---|
| Cifrado simétrico | AES (128/192/256 bits) |
| Modos de operación | CBC (con PKCS7), CFB, OFB, CTR |
| IV | 16 bytes aleatorios por operación (`secrets.token_bytes`) |
| Cifrado asimétrico | RSA-OAEP con SHA-256 y MGF1-SHA256 |
| Serialización RSA | PKCS8 con `BestAvailableEncryption` |
| Generación de claves | `AESGCM.generate_key` + `secrets` |

> **Nota:** Los modos CFB, OFB y CTR no aplican padding ya que operan como cifrado de flujo. Solo CBC requiere padding PKCS7.

---

## Licencia

MIT
