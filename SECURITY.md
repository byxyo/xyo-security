# Security Policy — Security by Xyo

## Supported versions

Security fixes are provided for the latest released version of the plugin
(currently the 3.x line).

| Version | Supported |
|---------|-----------|
| 3.x     | ✅        |
| < 3.0   | ❌        |

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Email **security@xyo.dev** with:

* the plugin version,
* your WordPress and PHP versions,
* a description of the issue and steps to reproduce it.

## Scope

This plugin hardens a WordPress site (head cleanup, HTTP headers, REST API lock,
generic login errors, file integrity monitoring). It is a defence-in-depth layer,
not a guarantee against compromise. Reports about the plugin's own behaviour —
for example a bypass of the REST lock, a flaw in the integrity scanner, or data
exposure in `wp-content/uploads/xyo-security/` — are especially welcome.

## Our commitments

* Acknowledgement within 3 business days.
* A fix released as soon as reasonably possible, followed by coordinated
  disclosure.
* Supported versions: the latest released version of the plugin.

---

# Politique de sécurité — Security by Xyo

## Signaler une vulnérabilité

Merci de **ne pas** ouvrir d'issue publique. Écrivez à **security@xyo.dev** en
précisant la version du plugin, vos versions de WordPress et PHP, une
description et les étapes de reproduction.

## Périmètre

Ce plugin durcit WordPress (nettoyage du <head>, en-têtes HTTP, verrouillage de
l'API REST, erreurs de login génériques, surveillance d'intégrité des fichiers).
C'est une couche de défense en profondeur, pas une garantie contre toute
compromission.

## Engagements

* Accusé de réception sous 3 jours ouvrés.
* Correctif publié dès que possible, puis divulgation coordonnée.
* Versions prises en charge : la dernière version publiée du plugin.
