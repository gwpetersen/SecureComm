import java.io.File;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
public class Encryption {
	
	
	/**
	 * this is the main method the first thing thats done is I 
	 * call the generate RSA method from bob to load the public and private 
	 * key pairs that will be used to encrypt the aes key
	 * 
	 * then i send a text file that contains data i want encrypted into the encrypt method
	 * 
	 * @param args
	 * @throws Exception
	 */
	
	public static void main(String[] args) throws Exception {
		Decryption dobj = new Decryption();
		// this generates the public and private keypair and then sends them to a file
		Decryption.generateRSA();
		
		
		
		
		 Encryption obj = new Encryption();
		  obj.encrypt("clear.txt"); //text encrypted with aes key
		  
		  
		 
		  
		  
	}
	
	
	/**
	 * 
	 * @param fname holds the file to be encrypted "clear.txt"
	 * @throws Exception
	 * This method encrypts the data from the clear.txt file using an "AES" key/algorithm
	 * She also sends her aes key she used to encrypt the data to a method called encryptAESKey
	 * Where the AES key she used will be encrypted using an RSA Algorithm
	 * Once the AES key is encrypted BOB will receive an encrypted key he must first decrypt before
	 * decrypting the data
	 * 
	 * 
	 */
	
	public void encrypt(String fname) throws Exception{
		  KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		  keyGen.init(128);  //using AES-256 doesnt work for strictly aes...so had to use 128 and then aes encryption works
		  SecretKey aeskey = keyGen.generateKey();  //generating key
		  
		  
		  byte[] raw = aeskey.getEncoded();
			FileOutputStream fos3 = new FileOutputStream("aeskey.txt"); //wrote the aes key to a file
			fos3.write(raw);
			fos3.close();
		  
		  
		  Cipher aesCipher = Cipher.getInstance("AES");  //getting cipher for AES
		  aesCipher.init(Cipher.ENCRYPT_MODE, aeskey);  //initializing cipher for encryption with key
		   
		  //creating file output stream to write to file
		  try(FileOutputStream fos = new FileOutputStream(fname+".aes"))
		  {          
		 
		 
		   //creating file input stream to read contents for encryption
			  try(FileInputStream fis = new FileInputStream(fname))
			  {
				  //creating cipher output stream to write encrypted contents
				  try(CipherOutputStream cos = new CipherOutputStream(fos, aesCipher))
				  {
					  int read;
					  byte buf[] = new byte[4096];
					  while((read = fis.read(buf)) != -1)  //reading from file
					   cos.write(buf, 0, read);  //encrypting and writing to file
				  }
				  
		  }
		  
			  byte[] data = Files.readAllBytes(new File("clear.txt.aes").toPath()); //reading the bytes from the encrypted data file
			  
			  
			  
			  String dataBeforeMAC = Base64.getEncoder().encodeToString(data);
			  System.out.println("Alice: this is the ecnrypted data before mac was applied, encrypted data is read from file clear.txt.aes ");
			  System.out.println("Alice: " +dataBeforeMAC);
			  
			  // creating an aes key that will be used with my MAC
			  // this key will also be saved to a file so bob can access this public key to also verify the mac
			  
			  KeyGenerator gen = KeyGenerator.getInstance("AES");
			  SecureRandom random = new SecureRandom(); // cryptograph. secure random 
			  keyGen.init(random); 
			  SecretKey secretKey = gen.generateKey();
			  
			  
			  byte[] mackey = secretKey.getEncoded();
			  FileOutputStream fos4 = new FileOutputStream("mackey.txt"); //wrote the aes key to a file this will be used just for the mac 
				fos4.write(mackey);
				fos4.close();
			 
				
				
				
			 hmac( data, secretKey); // create the hmac sending the data and the secretkey (aes) generated above
			 
			 
			// NOTHING BEYOND THIS STEP WILL BE DONE UNLESS BOB IS ABLE TO VERIFY THE MAC THAT IS SENT

		  
		  // prints out the aes key used in original encryption this key will soon me encrpted by alice using bobs public rsa key
		  String notEncryptedKey = Base64.getEncoder().encodeToString(aeskey.getEncoded());
		  System.out.println("Alice: aes key non encrypted "+ notEncryptedKey);
		  
		  
		  System.out.println("Alice: encrypted the clear.txt file she will now encrypt her key used in the encryption");
		  
		  File fileAESkey = new File("aeskey.txt"); //reading in bytes of aes key
			FileInputStream fis2 = new FileInputStream(fileAESkey);
			byte[] aesKey = new byte[fis2.available()];
			fis2.read(aesKey);
			fis2.close();
		  
		  byte [] skey = encryptAESKey(aesKey); //returns an RSA encrypted key
		  
		  
		  
		  Decryption dobj = new Decryption();
		   
		  
		  // skey at this point is = to the encrypted aes key
		  
		  
		  System.out.println("Bob: first decrypt the key to get the right aes key");
		  dobj.decryptAESKey(skey);
		  }
		  
		  
		 }
	
	/**
	 * this method will create the mac of the encrypted data
	 * the mac and the data is sent to bob
	 * bob will have to verify this mac before any decrypting the secret message 
	 * 
	 * @param data encrypted aes data
	 * @param hmackey aes key used
	 * @return bytes of now encrypted data with hmac appended to it
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws IOException
	 */
		
	
	private byte[] hmac(byte[] data, Key hmackey) throws NoSuchAlgorithmException, InvalidKeyException, IOException 
	{  
		
		
		
			Mac mac = Mac.getInstance("HmacSHA1"); //creating the mac
			mac.init(hmackey); //using an aes key generated in the encrypt method above. the aes key is a symmetric key so both bob and alice can have this key
			byte [] macdata = mac.doFinal(data); // appending the mac to the encrypted data
			
			String dataAfterMac = Base64.getEncoder().encodeToString(macdata);
			System.out.println("Alice: this is the encrypted data after mac was applied it will be sent to bob to be verified");
			System.out.println("Alice: " +dataAfterMac);
			
			Decryption obj = new Decryption(); 
			  obj.verifyMAC(data, hmackey, macdata);
			
			return macdata; // the encrypted data with the mac appended
		
		
	}


	/**
	 * 
	 * @param skey
	 * @return key of bytes the newly generated rsa public key
	 * this method will encrypt the aes key with rsa using BOBs public RSA key
	 * hence realize the get used is being genereated through a loadPublicKey method from BOB
	 * @throws Exception 
	 * @throws InvalidKeyException 
	 *
	 * 
	 */
	
	public byte[] encryptAESKey(byte[] aeskey) throws InvalidKeyException, Exception{
		Cipher cipher;
		byte[] encryptedAES = null;
		cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, loadPublicKey()); // using bobs public rsa key retrieved from the file
		encryptedAES = cipher.doFinal(aeskey);
		
        String rsakeyused = Base64.getEncoder().encodeToString(loadPublicKey().getEncoded());
		
		System.out.println("Alice: aes key successfully encrypted using BOBS rsa public key: " + rsakeyused);
		
		
		return encryptedAES;
		
	
		
		
	}
	
	/**
	 * this method reads in bobs public key from a file and converts it to publickey
	 * the key is encoded with ASN.1
	 * @return PublicKey from bob
	 * @throws Exception
	 */
	PublicKey loadPublicKey() throws Exception {
		
		
		File filePublicKey = new File("publickey.txt"); //reading in bytes of aes key
		FileInputStream fis = new FileInputStream(filePublicKey);
		byte[] encodedPublicKey = new byte[fis.available()];
		fis.read(encodedPublicKey);
		fis.close();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
				encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		return publicKey; // turned rsa key of bytes into type key 
	}
	
	
	
	

	
		
	
	
	
}