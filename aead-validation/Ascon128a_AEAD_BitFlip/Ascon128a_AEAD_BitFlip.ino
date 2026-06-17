#include <ASCON.h>
#include <string.h>

#define MAXLEN 96

static const uint8_t key[16] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t nonce[16] = {
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

static const uint8_t plaintext[] = "temp=23.5C;lux=00812;batt=98"; // payload
static const uint8_t adata[]     = "devEUI=42fb8334;fcnt=00128";   // cabecalho LoRaWAN

static const size_t ptlen = sizeof(plaintext) - 1;  // -1: ignora o terminador '\0'
static const size_t adlen = sizeof(adata) - 1;

static uint8_t validCt[MAXLEN];  // ciphertext || tag do pacote valido
static size_t  clen = 0;

struct Result { int tested; int rejected; };

// Decifra (ct, ad) e diz se foi CORRETAMENTE REJEITADO (tag invalida -> r < 0).
static bool decryptRejected(const uint8_t *ct, size_t ctlen,
                            const uint8_t *ad, size_t adl)
{
  uint8_t out[MAXLEN];
  size_t  mlen = 0;
  int r = ascon128a_aead_decrypt(out, &mlen, ct, ctlen, ad, adl, nonce, key);
  return r < 0;
}

// Vira cada bit da regiao [lo, hi) do buffer (ciphertext || tag) e confere rejeicao.
static Result flipCtRegion(size_t lo, size_t hi)
{
  Result r = {0, 0};
  uint8_t tmp[MAXLEN];

  for (size_t i = lo; i < hi; i++) {
    for (int b = 0; b < 8; b++) {
      memcpy(tmp, validCt, clen);
      tmp[i] ^= (uint8_t)(1 << b);
      r.tested++;

      if (decryptRejected(tmp, clen, adata, adlen)) {
        r.rejected++;
      }
    }
  }
  return r;
}

// Vira cada bit dos dados associados e confere rejeicao (ciphertext intacto).
static Result flipAd()
{
  Result r = {0, 0};
  uint8_t tmpad[MAXLEN];

  for (size_t i = 0; i < adlen; i++) {
    for (int b = 0; b < 8; b++) {
      memcpy(tmpad, adata, adlen);
      tmpad[i] ^= (uint8_t)(1 << b);
      r.tested++;

      if (decryptRejected(validCt, clen, tmpad, adlen)) {
        r.rejected++;
      }
    }
  }
  return r;
}

void setup()
{
  Serial.begin(115200);
  delay(300);
  Serial.println();
  Serial.println("=== Ascon-128a AEAD bit-flipping (Secao 3.4.2) ===");

  // (1) Gera um pacote valido.
  ascon128a_aead_encrypt(validCt, &clen, plaintext, ptlen, adata, adlen, nonce, key);

  Serial.print("Pacote valido: ");
  Serial.print((unsigned) ptlen); Serial.print(" B de texto claro + ");
  Serial.print((unsigned) adlen); Serial.print(" B de AD -> ");
  Serial.print((unsigned) clen);  Serial.println(" B (ciphertext || tag)");

  // (2) Controle: o pacote intacto deve ser ACEITO e recuperar o texto claro.
  uint8_t out[MAXLEN];
  size_t  mlen = 0;

  int rc = ascon128a_aead_decrypt(out, &mlen, validCt, clen, adata, adlen, nonce, key);
  bool ctrlOk = (rc >= 0) && (mlen == ptlen) && (memcmp(out, plaintext, ptlen) == 0);

  Serial.print("Controle (pacote intacto): ");
  Serial.println(ctrlOk ? "ACEITO, texto claro recuperado (OK)" : "FALHOU (inesperado)");
  Serial.println();

  // (3) Tres frentes de adulteracao: cada bit virado deve ser REJEITADO.
  Serial.println("Adulteracao por bit-flipping (cada bit deve ser REJEITADO):");

  Result ct  = flipCtRegion(0, ptlen);      // texto cifrado
  Serial.print("  Ciphertext : "); Serial.print(ct.rejected);  Serial.print("/"); Serial.print(ct.tested);  Serial.println(" rejeitados");

  Result ad  = flipAd();                     // dados associados
  Serial.print("  AD         : "); Serial.print(ad.rejected);  Serial.print("/"); Serial.print(ad.tested);  Serial.println(" rejeitados");

  Result tag = flipCtRegion(ptlen, clen);    // tag de autenticacao (ultimos 16 B)
  Serial.print("  Tag        : "); Serial.print(tag.rejected); Serial.print("/"); Serial.print(tag.tested); Serial.println(" rejeitados");

  int tested   = ct.tested   + ad.tested   + tag.tested;
  int rejected = ct.rejected + ad.rejected + tag.rejected;

  Serial.println();
  Serial.print("Total: "); Serial.print(rejected); Serial.print("/"); Serial.print(tested);
  Serial.println(" adulteracoes de 1 bit rejeitadas");

  if (ctrlOk && rejected == tested)
    Serial.println(">>> AEAD OK: pacote intacto aceito, toda adulteracao rejeitada <<<");
  else
    Serial.println(">>> FALHA: ver acima <<<");
}

void loop()
{
  delay(1000);
}
