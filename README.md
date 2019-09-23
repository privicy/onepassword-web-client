# OnePassword Web Client

## Class Hierarchy

### Methods

- [addAccount](README.md#addaccount)
- [getAccounts](README.md#getaccounts)
- [getAccountCredentials](README.md#getaccountcredentials)
- [login](README.md#login)

## Methods

### addAccount

▸ **addAccount**(`entry`: [RawEntry]): _Promise‹boolean›_

**Parameters:**

| Name    | Type       |
| ------- | ---------- |
| `entry` | [RawEntry] |

**Returns:** _Promise‹boolean›_

---

### getAccounts

▸ **getAccounts**(): _Promise‹[Entry]_

**Returns:** _Promise_

---

### getAccountCredentials

▸ **getAccountCredentials**(): _Promise‹[EntryCredentials]_

**Returns:** _Promise_

---

### login

▸ **login**(`password`: string, `username`: string, `secret`: string): _Promise‹void›_

**Parameters:**

| Name       | Type   |
| ---------- | ------ |
| `password` | string |
| `username` | string |
| `secret`   | string |

**Returns:** _Promise‹void›_

## Type aliases

### RawEntry

Ƭ **RawEntry**: _Record‹[RawEntryFields](README.md#rawentryfields), string›_

---

### RawEntryFields

Ƭ **RawEntryFields**: \_"name" | "url" | "type" | "username" | "password" | "otp"

---

### Entry

Ƭ **Entry**: _Record‹[EntryFields](README.md#entryfields), string›_

---

### EntryFields

Ƭ **EntryFields**: \_"name" | "url" | "type"

---

### EntryCredentials

Ƭ **EntryCredentials**: _Record‹[EntryCredentialsFields](README.md#entrycredentialsfields), string›_

---

### EntryCredentialsFields

Ƭ **EntryCredentialsFields**: \_"username" | "password" | "otp";

---
