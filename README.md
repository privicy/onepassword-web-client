# OnePassword Web Client

## Class Hierarchy

### Methods

- [addEntry](README.md#addentry)
- [getEntries](README.md#getentries)
- [getEntryCredentials](README.md#getentrycredentials)
- [login](README.md#login)

## Methods

### addEntry

▸ **addEntry**(`entry`: [NewEntry]): _Promise‹boolean›_

**Parameters:**

| Name    | Type       |
| ------- | ---------- |
| `entry` | [NewEntry] |

**Returns:** _Promise‹boolean›_

---

### getEntries

▸ **getEntries**(): _Promise‹[Entry]_

**Returns:** _Promise_

---

### getEntryCredentials

▸ **getEntryCredentials**(`entryId`: string): _Promise‹[EntryCredentials]_

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

### NewEntry

Ƭ **NewEntry**: _Record‹[NewEntryFields](README.md#rawentryfields), string›_

---

### NewEntryFields

Ƭ **NewEntryFields**: \_"id" | "name" | "url" | "type" | "username" | "password" | "otp"

---

### Entry

Ƭ **Entry**: _Record‹[EntryFields](README.md#entryfields), string›_

---

### EntryFields

Ƭ **EntryFields**: \_"id" | "name" | "url" | "type"

---

### EntryCredentials

Ƭ **EntryCredentials**: _Record‹[EntryCredentialsFields](README.md#entrycredentialsfields), string›_

---

### EntryCredentialsFields

Ƭ **EntryCredentialsFields**: \_"username" | "password" | "otp";

---
