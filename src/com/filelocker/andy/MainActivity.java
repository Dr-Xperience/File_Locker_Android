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

package com.filelocker.andy;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;

import android.app.Activity;
import android.app.Dialog;
import android.os.Bundle;
import android.view.Menu;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;
import ar.com.daidalos.afiledialog.FileChooserDialog;

import com.filelocker.andy.R;
import com.filelocker.encryption.AES_Encryption;

public class MainActivity extends Activity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	public void browseButton_Click(View view)
	{
		final TextView vFileChooserText =(TextView)findViewById(R.id.fileChooserText);
		final FileChooserDialog dialog = new FileChooserDialog(this);
	     dialog.show();
	     dialog.addListener(new FileChooserDialog.OnFileSelectedListener() {
	         public void onFileSelected(Dialog source, File file) {
	             source.hide();
	             Toast toast = Toast.makeText(source.getContext(), "File selected: " + file.getName(), Toast.LENGTH_LONG);
	             toast.show();
	             vFileChooserText.setText(file.getAbsolutePath());
	             dialog.hide();
	         }
	         public void onFileSelected(Dialog source, File folder, String name) {
	             source.hide();
	             Toast toast = Toast.makeText(source.getContext(), "File created: " + folder.getName() + "/" + name, Toast.LENGTH_LONG);
	             toast.show();
	             dialog.hide();
	         }
	     });
	}


	public void lockButton_Click(View view)
	{

		TextView vPasswordText = (TextView)findViewById(R.id.passwordText);
		TextView vFileChooserText =(TextView)findViewById(R.id.fileChooserText);

		String myPassword=vPasswordText.getText().toString();

		vPasswordText.setText("");

		if(vFileChooserText.getText().toString().equals("")||myPassword.equals(""))
		{
			Toast toast;
			if(vFileChooserText.getText().toString().equals(""))
			{
				toast=Toast.makeText(getApplicationContext(), "File Not Choosen",Toast.LENGTH_LONG);
				toast.show();
			}
			else if (myPassword.equals("") )
			{
				toast=Toast.makeText(getApplicationContext(), "Password Field Empty",Toast.LENGTH_LONG);
				toast.show();
			}


			return;
		}
		else if(!(vFileChooserText.getText().toString().substring(vFileChooserText.getText().toString().lastIndexOf('.') + 1).equals("encrypt")))
		{

			AES_Encryption en = new AES_Encryption (myPassword);
			/*
			 * setup encryption cipher using password. print out iv and salt
			 */
			try
			{
				File vInFile= new File(vFileChooserText.getText().toString());

				if(vInFile.exists()==false)
				{
					throw new FileNotFoundException("File Not Found");
				}

				en.setupEncrypt ();
			}
			catch (InvalidKeyException ex)
			{
				ex.printStackTrace();
			}
			catch (NoSuchAlgorithmException ex)
			{
				ex.printStackTrace();
			}
			catch (InvalidKeySpecException ex)
			{
				ex.printStackTrace();
			}
			catch (NoSuchPaddingException ex)
			{
				ex.printStackTrace();
			}
			catch (InvalidParameterSpecException ex)
			{
				ex.printStackTrace();
			}
			catch (IllegalBlockSizeException ex)
			{
				ex.printStackTrace();
			}
			catch (BadPaddingException ex)
			{
				ex.printStackTrace();
			}
			catch (UnsupportedEncodingException ex)
			{
				ex.printStackTrace();
			}
			catch(FileNotFoundException ex)
			{
				ex.printStackTrace();
			}

			/*
			 * write out encrypted file
			 */
			try
			{

				File vInFile= new File(vFileChooserText.getText().toString());
				File vOutFile = new File(vFileChooserText.getText().toString()+".encrypt");

				if(vInFile.exists()==false)
				{
					throw new FileNotFoundException("File Not Found");
				}

				en.WriteEncryptedFile (vInFile, vOutFile);

				Toast toast=Toast.makeText(getApplicationContext(), "Encryption Complete",Toast.LENGTH_LONG);
				toast.show();
				vInFile.delete();

			}
			catch (IllegalBlockSizeException ex)
			{
				ex.printStackTrace();
			}
			catch (BadPaddingException ex)
			{
				ex.printStackTrace();
			}
			catch (IOException ex)
			{
				ex.printStackTrace();
			}
		}
		else
		{

			/*
			 * decrypt file
			 */
			AES_Encryption dc = new AES_Encryption (myPassword);
			try
			{
				File vInFile= new File(vFileChooserText.getText().toString());

				if(vInFile.exists()==false)
				{
					throw new FileNotFoundException("File Not Found");
				}

				dc.setupDecrypt (vInFile);
			}
			catch (InvalidKeyException ex)
			{
				ex.printStackTrace();
			}
			catch (NoSuchAlgorithmException ex)
			{
				ex.printStackTrace();
			}
			catch (InvalidKeySpecException ex)
			{
				ex.printStackTrace();
			}
			catch (NoSuchPaddingException ex)
			{
				ex.printStackTrace();
			}
			catch (InvalidAlgorithmParameterException ex)
			{
				ex.printStackTrace();
			}
			catch (DecoderException ex)
			{
				ex.printStackTrace();
			}
			catch (IOException ex) {

				ex.printStackTrace();
			}


			/*
			 * write out decrypted file
			 */
			try
			{
				File vInFile= new File(vFileChooserText.getText().toString());
				File vOutFile = new File(vFileChooserText.getText().toString().substring(0, vFileChooserText.getText().toString().length() - 8));

				if(vInFile.exists()==false)
				{
					throw new FileNotFoundException("File Not Found");
				}

				dc.ReadEncryptedFile (vInFile, vOutFile);
				vInFile.delete();

				Toast toast = Toast.makeText(getApplicationContext(), "Decryption Complete",Toast.LENGTH_LONG);
				toast.show();
			}
			catch (IllegalBlockSizeException ex)
			{
				ex.printStackTrace();
			}
			catch (BadPaddingException ex)
			{
				ex.printStackTrace();
			}
			catch (IOException ex)
			{
				ex.printStackTrace();
			}
			catch(Exception ex)
			{
				ex.printStackTrace();
			}
		}

	}

	public void closeButton_Click(View view)
	{
		android.os.Process.killProcess(android.os.Process.myPid());
	}

}
