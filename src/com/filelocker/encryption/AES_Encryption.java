/****************************************************************************
    File Locker : Application to lock a file using AES Encryption with a password
    Copyright (C) 2013  Anubhav Arun <dr.xperience@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*****************************************************************************/

/**
 *
 */
package com.filelocker.encryption;

/** *********************************************************************************
 * TITLE        : THE CLASS TO CREATE THE AES PASSWORD ENCRYPTION LOGIC
 * AUTHOR       : RK10R04A01;11000527;ANUBHAV ARUN GUPTA
 * DATE/TIME    : AD 2013.07.30.13.12
 * IDE       	: Kepler Release Build id: 20130614-0229
 * JAVA VERSION : 1.7.0_25
 * JRE          : java version "1.7.0_25" Java(TM) SE Runtime Environment (build 1.7.0_25-b16)
 * ************************************************************************************* */


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
//import org.apache.commons.codec.android.binary.Hex;

public class AES_Encryption
{
	String vPassword = null;
	public final static int SALT_LEN = 8;
	byte [] vInitVec = null;
	byte [] vSalt = null;
	Cipher vEcipher = null;
	Cipher vDecipher = null;
	private final int KEYLEN_BITS = 128;
	private final int ITERATIONS = 65536;
	private final int MAX_FILE_BUF = 1024;

	/**
	 * create an object with just the passphrase from the user.
	 * @param password
	 */
	public AES_Encryption (String password)
	{
		vPassword = password;
	}

	/**
	 * return the generated salt for this object
	 * @return
	 */
	public byte [] getSalt ()
	{
		return (vSalt);
	}

	/**
	 * return the initialization vector created from setupEncryption
	 * @return
	 */
	public byte [] getInitVec ()
	{
		return (vInitVec);
	}

	/**
	 * debug/print messages
	 * @param msg
	 */
	private void Db (String msg)
	{
		System.out.println ("** Crypt ** " + msg);
	}

	/**
	 * this must be called after creating the initial Crypto object. It creates a salt of SALT_LEN bytes
	 * and generates the salt bytes using secureRandom().  The encryption secret key is created
	 * along with the initialization vectory. The member variable vEcipher is created to be used
	 * by the class later on when either creating a CipherOutputStream, or encrypting a buffer
	 * to be written to disk.
	 *
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidParameterSpecException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidKeyException
	 */
	public void setupEncrypt () throws NoSuchAlgorithmException,
	InvalidKeySpecException,
	NoSuchPaddingException,
	InvalidParameterSpecException,
	IllegalBlockSizeException,
	BadPaddingException,
	UnsupportedEncodingException,
	InvalidKeyException
	{
		SecretKeyFactory factory = null;
		SecretKey tmp = null;

		// crate secureRandom salt and store  as member var for later use
		vSalt = new byte [SALT_LEN];
		SecureRandom rnd = new SecureRandom ();
		rnd.nextBytes (vSalt);
		//Db ("generated salt :" + Hex.encodeHexString (vSalt));

		factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

		/* Derive the key, given password and salt.
		 *
		 * in order to do 256 bit crypto, you have to muck with the files for Java's "unlimted security"
		 * The end user must also install them (not compiled in) so beware.
		 * see here:  http://www.javamex.com/tutorials/cryptography/unrestricted_policy_files.shtml
		 */
		KeySpec spec = new PBEKeySpec (vPassword.toCharArray (), vSalt, ITERATIONS, KEYLEN_BITS);
		tmp = factory.generateSecret (spec);
		SecretKey secret = new SecretKeySpec (tmp.getEncoded(), "AES");

		/* Create the Encryption cipher object and store as a member variable
		 */
		vEcipher = Cipher.getInstance ("AES/CBC/PKCS5Padding");
		vEcipher.init (Cipher.ENCRYPT_MODE, secret);
		AlgorithmParameters params = vEcipher.getParameters ();

		// get the initialization vectory and store as member var
		vInitVec = params.getParameterSpec (IvParameterSpec.class).getIV();

		//Db ("vInitVec is :" + Hex.encodeHexString (vInitVec));
	}



	/**
	 * If a file is being decrypted, we need to know the pasword, the salt and the initialization vector (iv).
	 * We have the password from initializing the class. pass the iv and salt here which is
	 * obtained when encrypting the file initially.
	 *
	 * @param inFile - The Encrypted File containing encrypted data , salt and InitVec
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws DecoderException
	 * @throws IOException
	 */
	public void setupDecrypt (File inFile) throws NoSuchAlgorithmException,
	InvalidKeySpecException,
	NoSuchPaddingException,
	InvalidKeyException,
	InvalidAlgorithmParameterException,
	DecoderException,
	IOException
	{
		SecretKeyFactory factory = null;
		SecretKey tmp = null;
		SecretKey secret = null;


		byte[] vSalt = new byte[8];
		byte[] vInitVec = new byte[16];

		RandomAccessFile vFile = new RandomAccessFile(inFile,"rw");

		//The last 8 bits are salt so seek to length of file minus 9 bits
		vFile.seek(vFile.length()-8);
		vFile.readFully(vSalt);

		//The last 8 bits are salt and 16 bits before last 8 are Initialization Vectory so 8+16=24
		//Thus to seek to length of file minus 24 bits
		vFile.seek(vFile.length()-24);
		vFile.readFully(vInitVec);

		vFile.seek(0);

		File tmpFile = new File(inFile.getAbsolutePath()+".tmpEncryption.file");

		RandomAccessFile vTmpFile = new RandomAccessFile(tmpFile,"rw");

		for(int i=0; i<(vFile.length()-24);++i)
		{
			vTmpFile.write(vFile.readByte());
		}
		vFile.close();
		vTmpFile.close();

		inFile.delete();
		tmpFile.renameTo(inFile);



		//Db ("got salt " + Hex.encodeHexString (vSalt));

		//Db ("got initvector :" + Hex.encodeHexString (vInitVec));


		/* Derive the key, given password and salt. */
		// in order to do 256 bit crypto, you have to muck with the files for Java's "unlimted security"
		// The end user must also install them (not compiled in) so beware.
		// see here:
		// http://www.javamex.com/tutorials/cryptography/unrestricted_policy_files.shtml
		// PBKDF2WithHmacSHA1,Constructs secret keys using the Password-Based Key Derivation Function function
		//found in PKCS #5 v2.0. (PKCS #5: Password-Based Cryptography Standard)

		factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec spec = new PBEKeySpec(vPassword.toCharArray (), vSalt, ITERATIONS, KEYLEN_BITS);

		tmp = factory.generateSecret(spec);
		secret = new SecretKeySpec(tmp.getEncoded(), "AES");

		// Decrypt the message, given derived key and initialization vector.
		vDecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		vDecipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(vInitVec));
	}


	/**
	 * This is where we write out the actual encrypted data to disk using the Cipher created in setupEncrypt().
	 * Pass two file objects representing the actual input (cleartext) and output file to be encrypted.
	 *
	 * @param input - the cleartext file to be encrypted
	 * @param output - the encrypted data file
	 * @throws IOException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public void WriteEncryptedFile (File input, File output) throws
	IOException,
	IllegalBlockSizeException,
	BadPaddingException
	{
		FileInputStream fin;
		FileOutputStream fout;
		long totalread = 0;
		int nread = 0;
		byte [] inbuf = new byte [MAX_FILE_BUF];

		fout = new FileOutputStream (output);
		fin = new FileInputStream (input);

		while ((nread = fin.read (inbuf)) > 0 )
		{
			Db ("read " + nread + " bytes");
			totalread += nread;

			// create a buffer to write with the exact number of bytes read. Otherwise a short read fills inbuf with 0x0
			// and results in full blocks of MAX_FILE_BUF being written.
			byte [] trimbuf = new byte [nread];
			for (int i = 0; i < nread; i++)
				trimbuf[i] = inbuf[i];

			// encrypt the buffer using the cipher obtained previously
			byte [] tmp = vEcipher.update (trimbuf);

			// I don't think this should happen, but just in case..
			if (tmp != null)
				fout.write (tmp);
		}

		// finalize the encryption since we've done it in blocks of MAX_FILE_BUF
		byte [] finalbuf = vEcipher.doFinal ();
		if (finalbuf != null)
			fout.write (finalbuf);

		fout.write(vInitVec);
		fout.write(vSalt);
		fout.flush();
		fin.close();
		fout.close();
		fout.close ();

		Db ("wrote " + totalread + " encrypted bytes");
		Db ("Encryption Complete File Locked");
	}


	/**
	 * Read from the encrypted file (input) and turn the cipher back into cleartext. Write the cleartext buffer back out
	 * to disk as (output) File.
	 *
	 * I left CipherInputStream in here as a test to see if I could mix it with the update() and final() methods of encrypting
	 *  and still have a correctly decrypted file in the end. Seems to work so left it in.
	 *
	 * @param input - File object representing encrypted data on disk
	 * @param output - File object of cleartext data to write out after decrypting
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 */
	public void ReadEncryptedFile (File input, File output) throws
	IllegalBlockSizeException,
	BadPaddingException,
	IOException
	{
		FileInputStream fin;
		FileOutputStream fout;
		CipherInputStream cin;
		long totalread = 0;
		int nread = 0;
		byte [] inbuf = new byte [MAX_FILE_BUF];

		fout = new FileOutputStream (output);
		fin = new FileInputStream (input);

		// creating a decoding stream from the FileInputStream above using the cipher created from setupDecrypt()
		cin = new CipherInputStream (fin, vDecipher);

		while ((nread = cin.read (inbuf)) > 0 )
		{
			Db ("read " + nread + " bytes");
			totalread += nread;

			// create a buffer to write with the exact number of bytes read. Otherwise a short read fills inbuf with 0x0
			byte [] trimbuf = new byte [nread];
			for (int i = 0; i < nread; i++)
				trimbuf[i] = inbuf[i];

			// write out the size-adjusted buffer
			fout.write (trimbuf);
		}

		//		while ((nread = fin.read (inbuf)) > 0 )
		//		{
		//			Db ("read " + nread + " bytes");
		//			totalread += nread;
		//
		//			// create a buffer to write with the exact number of bytes read. Otherwise a short read fills inbuf with 0x0
		//			// and results in full blocks of MAX_FILE_BUF being written.
		//			byte [] trimbuf = new byte [nread];
		//			for (int i = 0; i < nread; i++)
		//				trimbuf[i] = inbuf[i];
		//
		//			// encrypt the buffer using the cipher obtained previously
		//			byte [] tmp = vDecipher.update (trimbuf);
		//
		//			// I don't think this should happen, but just in case..
		//			if (tmp != null)
		//				fout.write (tmp);
		//		}

		fout.flush();
		cin.close();
		fin.close ();
		fout.close();

		Db ("wrote " + totalread + " dencrypted bytes");
		Db ("Decryption Complete File Unlocked");
	}

}

