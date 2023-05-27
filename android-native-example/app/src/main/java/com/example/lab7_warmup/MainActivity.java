package com.example.lab7_warmup;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'lab7_warmup' library on application startup.
    static {
        System.loadLibrary("lab7_warmup");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView flag = findViewById(R.id.Flag);
        Button button = findViewById(R.id.button_check);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (Check(flag.getText().toString())) {
                    Toast.makeText(getApplicationContext(), "RIGHT!", Toast.LENGTH_SHORT).show();
                }
                else
                    Toast.makeText(getApplicationContext(), "WRONG!", Toast.LENGTH_SHORT).show();
            }
        });
    }

    /**
     * A native method that is implemented by the 'lab7_warmup' native library,
     * which is packaged with this application.
     */
    public native boolean Check(String flag);
}