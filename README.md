# PixCrypt-Image-Encrypter

A software that allows you to encrypt an image. The image is first converted to string format(ASCII) using base64 and then encrypted using Advanced Encryption Standard(AES). The encrypted file is stored in .bin format.

The user can choose between 126/192/256 bit AES. The encrypted file will be saved in the same location as the original file. After encryption, there's an option to directly send the encrypted file as an email attatchment. For this, a google app password is required as google has disabled 3rd party access to less secure apps from June 2022 onwards. This can be generated from the user's google account.

The software can also be used to decrypt the image at the receiver's end and view the decrypted image.

The GUI of the software is implemented using CustomTkinter (https://github.com/TomSchimansky/CustomTkinter).

Applications of PixCrypt:-
Sensitive images can be encrypted and :-
1) Sent as an email attatchment to the receiver.
2) Given to the receiver using a pendrive containing the encrypted .bin files.
3) Stored in the user's pc as encrypted files and delete the original files.
