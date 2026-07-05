https://developer.hashicorp.com/vault/docs/auth/approle/approle-pattern#usage-workflow

# Trusted Party

## Approle erstellen
Erstelle eine neue AppRole mit den folgenden Parametern. Weitere Details: [Vault API Docs - Create/Update AppRole](https://developer.hashicorp.com/vault/api-docs/auth/approle#create-update-approle)

```bash
vault write auth/approle/role/my-role \
    token_type=batch \
    secret_id_bound_cidrs="0.0.0.0/0" \
    secret_id_ttl=0 \
    secret_id_num_uses=0 \
    token_ttl=20m \
    token_max_ttl=30m \
    token_num_uses=0 \
    token_policies=default,key1 \
    token_bound_cidrs="0.0.0.0/0"
```

## RoleID abrufen
```bash
vault read auth/approle/role/my-role/role-id
```

## Secret ID generieren
```bash
vault write -f auth/approle/role/my-role/secret-id
```

Hier ein vollständiges Beispiel für HashiCorp Vault **Cubbyhole** – inklusive Secret eintragen, Response Wrapping und Abruf über den Wrapped Token.

## 1. Secret in den Cubbyhole eintragen

Der `cubbyhole`-Secret-Engine ist token-gebunden – jedes Token hat seinen eigenen privaten Cubbyhole. Secrets liegen also nur für genau das Token sichtbar vor, das sie geschrieben hat.

```bash
vault write cubbyhole/mein-secret secret_id=SECRET_ID
```

Auslesen (nur mit demselben Token möglich):

```bash
vault read cubbyhole/mein-secret
```

Ausgabe:
```
Key         Value
---         -----
secret_id   SECRET_ID
```

## 2. Response Wrapping – Secret „einwickeln"

Beim Response Wrapping erzeugt Vault einen **einmalig verwendbaren Wrapping-Token**. Die eigentliche Antwort wird in einem temporären Cubbyhole abgelegt und kann nur **ein einziges Mal** über diesen Token entpackt werden. Der `-wrap-ttl` legt die Gültigkeitsdauer fest.

**Variante A – ein bestehendes Secret wrappen (z. B. aus dem KV-Store):**

```bash
vault kv get -wrap-ttl=120s cubbyhole/mein-secret
```

**Variante B – beliebige Daten direkt gewrappt schreiben:**

```bash
vault write -wrap-ttl=120s cubbyhole/transfer secret_id=SECRET_ID
```

Ausgabe (gekürzt):
```
Key                              Value
---                              -----
wrapping_token:                  hvs.CAESIJ...abcdef
wrapping_accessor:               GjykuM...
wrapping_token_ttl:              2m
wrapping_token_creation_time:    2026-06-29 09:53:00 +0200
wrapping_token_creation_path:    cubbyhole/transfer
```

Der Wert `wrapping_token` ist das, was du dem Empfänger übergibst (z. B. über einen sicheren Kanal). Die eigentlichen Daten sind darin **nicht** im Klartext enthalten.

# Machine

## 3. Secret über den Wrapped Token abrufen (unwrap)

Der Empfänger löst den Wrapping-Token mit `vault unwrap` ein:

```bash
vault unwrap -format=json s.1234567890abcdef | jq -r '.data.secret_id' | tr -d '\n' | keyctl padd user secret_id @u
```

Alternativ über die Umgebungsvariable bzw. das aktuelle Token:

```bash
VAULT_TOKEN=hvs.CAESIJ...abcdef vault unwrap
```

Ausgabe:
```
Key         Value
---         -----
secret_id   SECRET_ID
```

## Mit role_id und secret_id vault token holen
```
echo "$SECRET_ID" | vault write -field=token auth/approle/login role_id="<ROLE_ID>" secret_id=-
```
## Wichtige Eigenschaften / Sicherheitsmerkmale

- **Single-Use:** Ein Wrapping-Token kann nur **einmal** entpackt werden. Ein zweiter `unwrap`-Versuch schlägt fehl:
  ```
  Error unwrapping: wrapping token is not valid or does not exist
  ```
- **TTL-Ablauf:** Wird der Token nicht innerhalb der `-wrap-ttl` eingelöst, verfällt er automatisch und die Daten werden gelöscht.
- **Tamper-Erkennung:** Wurde der Token bereits benutzt (z. B. abgefangen und ausgelesen), erkennt der legitime Empfänger das sofort, weil sein `unwrap` fehlschlägt.
- **Gültigkeit prüfen** (ohne zu entpacken), z. B. über den Accessor:
  ```bash
  vault token lookup -accessor GjykuM...
  ```

## Typischer Anwendungsfall

Response Wrapping wird häufig für **sichere Secret-Übergabe** verwendet (Secure Introduction): Ein vertrauenswürdiges System (z. B. CI/CD oder ein Admin) erzeugt den Wrapping-Token und reicht ihn an eine Applikation/VM weiter. Diese entpackt ihn beim Start genau einmal. So muss das langlebige Secret nie im Klartext durch Logs, Pipelines oder Konfigurationsdateien wandern.
