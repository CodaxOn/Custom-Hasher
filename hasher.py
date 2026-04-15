import struct
import os

def hasher_strict():

    h0, h1, h2, h3 = 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A
    h4, h5, h6, h7 = 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    P = 0xFFFFFFFF
    SALT = 0x85ebca6b 

    message_clair = input("Entrez le message à hacher : ")
    pepper = os.getenv("MY_SECRET_PEPPER", "")
    intermediaire = message_clair + pepper
    
    print("Hachage en cours ...")

    for _ in range(50000):

        h0, h1, h2, h3 = 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A
        h4, h5, h6, h7 = 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
        
        data = bytearray(intermediaire, 'utf-8')
        taille_originale = len(data) & P 
        
        data.append(0x80) 
        
        while (len(data) + 4) % 4 != 0:
            data.append(0x00)
            
        data.extend(struct.pack('>I', taille_originale))
        
        for i in range(0, len(data), 4):
            bloc = int.from_bytes(data[i:i+4], byteorder='big')
            
            h0 ^= bloc
            h1 ^= (bloc ^ 0x55555555)
            h0 = ((h0 << 13) & P) | (h0 >> 19)
            h1 = ((h1 << 17) & P) | (h1 >> 15)
            h0 = (h0 * 2654435761) & P
            h1 = (h1 * 2246822519) & P
            h0 = ((h0 & 0x0000FFFF) << 16) | (h0 >> 16)
            h1 = ((h1 & 0x0F0F0F0F) << 4) | ((h1 & 0xF0F0F0F0) >> 4)
            h2 = (h2 ^ h0) + h1 & P
            h3 = (h3 ^ h1) + h0 & P

            h4 ^= bloc
            h5 ^= (bloc ^ 0xAAAAAAAA)
            h4 = ((h4 << 11) & P) | (h4 >> 21)
            h5 = ((h5 << 19) & P) | (h5 >> 13)
            h4 = (h4 * 0x85ebca6b) & P
            h5 = (h5 * 0xc2b2ae35) & P
            h4 = ((h4 & 0x0000FFFF) << 16) | (h4 >> 16)
            h5 = ((h5 & 0x0F0F0F0F) << 4) | ((h5 & 0xF0F0F0F0) >> 4)
            h6 = (h6 ^ h4) + h5 & P
            h7 = (h7 ^ h5) + h4 & P

        registres = [h0, h1, h2, h3, h4, h5, h6, h7]
        final_blocs = []
        for r in registres:
            f = r ^ 0xDEADBEEF               
            f = ((f << 7) & P) | (f >> 25)    
            f = (f * 0x45d9f3b) % P           
            f = f ^ SALT                      
            final_blocs.append(f)
        
        intermediaire = "".join(f"{b:08x}" for b in final_blocs)

    print(f"\nHash Final : {intermediaire}")

if __name__ == "__main__":
    hasher_strict()