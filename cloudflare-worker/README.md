# Documents privés : déploiement Cloudflare

Ce Worker ne doit être publié que sur un sous-domaine personnel protégé par **Cloudflare Access**. Il lit les fichiers dans un bucket R2 privé : aucun fichier ne doit être exposé par URL publique R2 ni stocké dans GitHub.

## Politique Access à créer dans Cloudflare

1. Créer l’application `https://documents.votre-domaine.fr`.
2. Autoriser l’authentification par e-mail à usage unique et imposer TOTP / clé de sécurité.
3. Activer **Temporary authentication**, avec vous comme approbateur, durée **1 heure** et justification obligatoire.
4. Mettre l’URL du sous-domaine sur le Worker, jamais sur `workers.dev`.
5. Reporter l’Audience (AUD) et le domaine d’équipe dans les variables du Worker.

Le QR code public doit pointer vers le sous-domaine Access. Cloudflare demande alors l’identité du visiteur ; vous choisissez d’accepter ou de refuser chaque demande.

## Publication des fichiers

Créer le bucket R2 privé, puis téléverser les PDF sous des noms simples, par exemple `permis-b.pdf`. Le Worker les sert uniquement après validation du JWT Cloudflare Access. Ne pas utiliser de bucket R2 public ou de lien présigné pour ce flux.
