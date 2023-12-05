import hashlib

def verifier_exigences_mot_de_passe(mot_de_passe):
    # Vérifie si le mot de passe respecte les exigences de sécurité
    longueur_minimale = 8
    contient_majuscule = any(c.isupper() for c in mot_de_passe)
    contient_minuscule = any(c.islower() for c in mot_de_passe)
    contient_chiffre = any(c.isdigit() for c in mot_de_passe)
    contient_special = any(c in "!@#$%^&*" for c in mot_de_passe)

    return (
        len(mot_de_passe) >= longueur_minimale and
        contient_majuscule and
        contient_minuscule and
        contient_chiffre and
        contient_special
    )

def hasher_mot_de_passe(mot_de_passe):
    # Utilise l'algorithme de hachage SHA-256 pour crypter le mot de passe
    hasher = hashlib.sha256()
    hasher.update(mot_de_passe.encode('utf-8'))
    mot_de_passe_crypte = hasher.hexdigest()
    return mot_de_passe_crypte

def main():
    while True:
        mot_de_passe = input("Choisissez un mot de passe : ")

        if verifier_exigences_mot_de_passe(mot_de_passe):
            mot_de_passe_crypte = hasher_mot_de_passe(mot_de_passe)
            print("Mot de passe valide. Mot de passe crypté :", mot_de_passe_crypte)
            break
        else:
            print("Le mot de passe ne respecte pas les exigences de sécurité. Veuillez choisir un nouveau mot de passe.")

if __name__ == "__main__":
    main()
