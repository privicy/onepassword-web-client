# Lastpass Client

## Class Hierarchy

### Methods

- [addAccount](README.md#addaccount)
- [getAccounts](README.md#getaccounts)
- [login](README.md#login)

## Methods

### addAccount

▸ **addAccount**(`entry`: [Entry]): _Promise‹boolean›_

**Parameters:**

| Name    | Type    |
| ------- | ------- |
| `entry` | [Entry] |

**Returns:** _Promise‹boolean›_

---

### getAccounts

▸ **getAccounts**(): _Promise‹[Entry]_

**Returns:** _Promise_

---

### login

▸ **login**(`username`: string, `password`: string, `otp?`: string): _Promise‹void›_

**Parameters:**

| Name       | Type   |
| ---------- | ------ |
| `username` | string |
| `password` | string |
| `otp?`     | string |

**Returns:** _Promise‹void›_

## Type aliases

### Entry

Ƭ **Entry**: _Record‹[EntryFields](README.md#entryfields), string›_

---

### EntryFields

Ƭ **EntryFields**: _"name" | "url" | "type" | "username" | "password" | "otp"_

---
