package com.example.keyboard_fpe;

import android.content.Context;
import android.graphics.Rect;
import android.os.Vibrator;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.widget.Toast;

import java.math.BigInteger;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("fpe-lib");
    }
    private int length1;
    private int length2;
    private int length3; //for aes

    private VelocityTracker mVelocityTracker;
    private static final int SWIPE_THRESHOLD_VELOCITY = 8; // 스와이프 인식시 속도
    private float curX, AUX;
    private float curY, AUY;
    private float X, Y, Y_R;
    private float rtop;
    private View f1;
    private Vibrator vibrator;
    private int sw, in, sum, b1, b2, b3, b4, b5, b6;
    private String result;
    private String result2;
    private String result3;
    private String result4; // for FEA_8 Encryption
    private String result5; // for FEA_8 Decryption
    private String split8; // for FEA_4 Encryption
    private String split8_1; // for FEA_4 Encryption
    private String split4; // for FEA_4 Decryption
    private String split4_1; // for FEA_4 Encryption
    private String result6; // for FEA_4 Encryption
    private String result7; // for FEA_4 Decryption
    private String result8;
    private String result9;
    private String result10;
    private String result11;
    private String aesresult;
    private String aesresult2;
    private String reminder;
    private String reminder2;
    private Rect r = new Rect();
    private char array[][] = {{'a','1','b',' ','k','2','l','@','c','i',
            'f','/','m','s','p',' ','e','3','h','9',
            'o','6','r','^','d','j','g','>','n','t',
            'q',',','*','5','<','-','u','8','v','.',
            '%','[','$','+','x','!','&',';',':','4',
            ' ','0','z','7','(',' ','?','w',']','#',
            'y',')','='},
            {'A',' ','B',' ','K',' ','L','`','C','I',
                    'F',' ','M','S','P',' ','E',' ','H',' ',
                    'O',' ','R','~','D','J','G',' ','N','T',
                    'Q',' ',' ',' ',' ',' ','U',' ','V',' ',
                    ' ','{',' ',' ','X',' ',' ',' ',' ',' ',
                    ' ',' ','Z',' ',' ','_',' ','W','}',' ',
                    'Y',' ',' '}};

    public static enum Action {
        LR, // Left to Right
        RL, // Right to Left
        TB, // Top to bottom
        BT, // Bottom to Top
        None // when no action was detected
    }

    private static final String logTag = "SwipeDetector";
    private float downX, downY, upX, upY;
    private Action mSwipeDetected = Action.None;

    public boolean swipeDetected() {
        return mSwipeDetected != Action.None;
    }

    public Action getAction() {
        return mSwipeDetected;
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {

        View layoutMainView = (View)this.findViewById(R.id.Frame1);
        f1.getGlobalVisibleRect(r);
        rtop = r.top;
        X = layoutMainView.getWidth();
        Y = layoutMainView.getHeight()+rtop;
        Y_R = Y/3;
        Log.w("Layout Width - ", String.valueOf(X));
        Log.w("Layout Height - ", String.valueOf(Y));
        Log.w("Layout Height - ", String.valueOf(rtop));
        Log.w("Layout Height - ", String.valueOf(Y_R));
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        vibrator = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
        //mGestureDetector = new GestureDetector(this, TestGestureListener);
        Log.d("MainActivity", "화면 띄우기");
        f1 = findViewById(R.id.Frame1);
        f1.setOnTouchListener(mTouchEvent);
        sw = 0;
        sum = 0;
        b1 = 0; b2 = 0; b3 = 0; b4 = 0; b5 = 0; b6 = 0;
        result = "";
        result2 = "";
        result3 = "";
        result4 = ""; // for FEA_8 Encryption
        result5 = ""; // for FEA_8 Decryption
        split8 = "";
        split4 = "";
        split8_1 = "";
        split4_1 = "";
        result6 = ""; // for FEA_4 Decryption
        result7 = ""; // for FEA_4 Decryption
        result8 = "";
        result9 = "";
        result10 = "";
        result11 = "";
        aesresult="";
        aesresult2 = "";
        reminder="";
        reminder2="";
        length1 = 0;
        length2 = 0;
        length3=0;

    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String encrypt(String str, int n);
    public native String decrypt(String str, int n);
    public native String aesenc(String str, int n);
    public native String tbcenc(String str);    // for 8byte FEA
    public native String tbcdec(String str, int n);    // for 8byte FEA
    public native String tbcenc4(String str);    // for 4byte FEA
    public native String tbcdec4(String str, int n);    // for 4byte FEA
    public native String KSTS(String str);

    private View.OnTouchListener mTouchEvent = new View.OnTouchListener() {

        @Override
        public boolean onTouch(View v, MotionEvent event) {
            if (mVelocityTracker == null) {
                mVelocityTracker = VelocityTracker.obtain();
            }
            mVelocityTracker.addMovement(event);
            if(event.getAction() == MotionEvent.ACTION_DOWN) {
                downX = event.getRawX();
                downY = event.getRawY();
                mSwipeDetected = Action.None;
            }
            if(event.getAction() == MotionEvent.ACTION_MOVE) {
                curX = event.getRawX();
                curY = event.getRawY();
                mVelocityTracker.computeCurrentVelocity(1);
                float velocityX = mVelocityTracker.getXVelocity();
                float velocitY = mVelocityTracker.getYVelocity();
                //Log.d("velocity : ", String.valueOf(velocityX) + '+' + String.valueOf(velocitY));

                float deltaX = downX - curX;
                float deltaY = downY - curY;
                if(mSwipeDetected == Action.None) {
                    if (Math.abs(velocityX) > SWIPE_THRESHOLD_VELOCITY) {
                        // left or right
                        if (deltaX < 0) {
                            Log.i(logTag, "Swipe Left to Right");       // 전송
                            mSwipeDetected = Action.LR;

                            if (sum != 0)            // 입력 완료(다음 입력)(좌->우)
                            {
                                if (sum == 56)        // 2번째 배열로 변경
                                    sw = 1;
                                else if (sw == 0)                // 1번째 배열 탐색
                                {
                                    if(array[0][sum - 1]!=' ')
                                        result += array[0][sum - 1];
                                    Log.d("result : ", array[0][sum - 1] + " : " + result);
                                    Toast.makeText(getApplicationContext(), result, Toast.LENGTH_SHORT).show();
                                } else {
                                    if(array[1][sum - 1]!=' ')
                                        result += array[1][sum - 1];
                                    Log.d("result : ", array[0][sum - 1] + " : " + result);
                                    Toast.makeText(getApplicationContext(), result, Toast.LENGTH_SHORT).show();
                                    sw = 0;
                                }
                                sum = 0;
                            }

                            b1 = 0; b2 = 0; b3 = 0; b4 = 0; b5 = 0; b6 = 0;

                            return false;
                        }
                        if (deltaX > 0) {
                            Log.i(logTag, "Swipe Right to Left");       // 지우기
                            mSwipeDetected = Action.RL;

                            if (sum != 0 || sw==1)        // 현재 입력중인 값이 있을 경우 입력중인 값 초기화
                            {
                                sum = 0;
                                sw = 0;
                                Toast.makeText(getApplicationContext(), result, Toast.LENGTH_SHORT).show();
                            }
                            else if (result.length()>0 && sw == 0)    // 입력중인 값이 없고 배열 1을 가리키는 경우 이전 값 제거
                            {
                                result = result.substring(0, result.length() - 1);
                                Toast.makeText(getApplicationContext(), result, Toast.LENGTH_SHORT).show();
                            }
                            sw = 0;

                            return false;
                        }
                    } else {
                        // vertical swipe detection
                        if (Math.abs(velocitY) > SWIPE_THRESHOLD_VELOCITY) {
                            // top or down
                            if (deltaY < 0) {
                                Log.i(logTag, "Swipe Top to Bottom");       // 전체전송
                                mSwipeDetected = Action.TB;

                                Log.d("plaintext : ", result+" "+result.length());

                                result2 = encrypt(result, result.length());
                                Log.d("ciphertext : ", result2+" "+result2.length());
                                result3 = decrypt(result2, result.length());

                                //KSTS("a");

                                if(result.length() == 12){
                                    KSTS("a");

                                    aesresult=aesenc(result,result.length());
                                    Log.d("aes ciphertext : ", aesresult+" "+aesresult.length());

                                    split8 = result.substring(0,8);
                                    split4 = result.substring(8);

                                    //for 8byte FEA --> start
                                    result4 = tbcenc(split8); // for FEA Encryption
                                    Log.d("FEA_enc", result4+",  "+ result4.length());
                                    result5 = tbcdec(result4, result4.length());        // for FEA Decryption
                                    result5 = result5.substring(0,8);
                                    Log.d("FEA_dec", result5 +",  "+ result5.length());
                                    result4 = result4.substring(0,8);
                                    //for 8byte FEA --> end

                                    //for 4byte FEA --> start
                                    result6 = tbcenc4(split4);
                                    result7 = tbcdec4(result6, result6.length());
                                    result7 = result7.substring(0,4);
                                    result6 = result6.substring(0,4);
                                    //for 4byte FEA --> end
                                    length1 = result4.length()+result6.length();
                                    length2 = result5.length()+result7.length();

                                    Log.d("plaintext : ", result3+" "+result3.length());
                                    Toast.makeText(getApplicationContext(), "plaintext ; " + result + ", "+result.length()+ "\nciphertext : " +
                                                    result2 + ", "+result2.length()+ "\nrecovery : "+
                                                    result3+ ", "+result3.length() + "\nAES 128 ciphertext : " + aesresult+ ", "+aesresult.length() +
                                                    "\nFEA_ciphertext : " + result4+result6 +", "+ length1 +
                                                    "\nFEA_recovery : "+ result5+result7 +", "+ length2
                                            , Toast.LENGTH_SHORT).show();
                                }
                                else if(result.length() == 16){
                                    KSTS("a");

                                    aesresult=aesenc(result,result.length());
                                    Log.d("aes ciphertext : ", aesresult+" "+aesresult.length());

                                    split8 = result.substring(0,8);
                                    split4 = result.substring(8);

                                    //for 8byte FEA --> start
                                    result4 = tbcenc(split8); // for FEA Encryption
                                    Log.d("FEA_enc", result4+",  "+ result4.length());
                                    result5 = tbcdec(result4, result4.length());        // for FEA Decryption
                                    result5 = result5.substring(0,8);
                                    Log.d("FEA_dec", result5 +",  "+ result5.length());
                                    result4 = result4.substring(0,8);
                                    //for 8byte FEA --> end

                                    //for 4byte FEA --> start
                                    result6 = tbcenc(split4);
                                    result7 = tbcdec(result6, result6.length());
                                    result7 = result7.substring(0,8);
                                    result6 = result6.substring(0,8);
                                    //for 4byte FEA --> end

                                    length1 = result4.length()+result6.length();
                                    length2 = result5.length()+result7.length();

                                    Log.d("plaintext : ", result3+" "+result3.length());
                                    Toast.makeText(getApplicationContext(), "plaintext ; " + result + ", "+result.length()+ "\nciphertext : " +
                                                    result2 + ", "+result2.length()+ "\nrecovery : "+
                                                    result3+ ", "+result3.length() + "\nAES 128 ciphertext : " + aesresult+ ", "+aesresult.length() +
                                                    "\nFEA_ciphertext : " + result4+result6 +", "+ length1 +
                                                    "\nFEA_recovery : "+ result5+result7 +", "+ length2
                                            , Toast.LENGTH_SHORT).show();
                                }
                                else if(result.length() == 20){
                                    KSTS("a");

                                    reminder = result.substring(0,16);
                                    reminder2 = result.substring(16);

                                    aesresult=aesenc(reminder,reminder.length());
                                    Log.d("aes ciphertext : ", aesresult+" "+aesresult.length());
                                    aesresult2 = aesenc(reminder2,reminder2.length());
                                    Log.d("aes ciphertext : ", aesresult2+" "+aesresult2.length());
                                    length3 = aesresult.length()+aesresult2.length();


                                    split8 = result.substring(0,8);
                                    split4 = result.substring(8,16);
                                    split4_1 = result.substring(16);

                                    //for 8byte FEA --> start
                                    result4 = tbcenc(split8); // for FEA Encryption
                                    Log.d("FEA_enc", result4+",  "+ result4.length());
                                    result5 = tbcdec(result4, result4.length());        // for FEA Decryption
                                    result5 = result5.substring(0,8);
                                    Log.d("FEA_dec", result5 +",  "+ result5.length());
                                    result4 = result4.substring(0,8);
                                    //for 8byte FEA --> end

                                    //for 8byte FEA --> start
                                    result6 = tbcenc(split4);
                                    result7 = tbcdec(result6, result6.length());
                                    result7 = result7.substring(0,8);
                                    result6 = result6.substring(0,8);
                                    //for 8byte FEA --> end

                                    //for 8byte FEA --> start
                                    result8 = tbcenc4(split4_1);     // 계속 에러남
                                    result9 = tbcdec4(result8, result8.length());
                                    result9 = result9.substring(0,4);
                                    result8 = result8.substring(0,4);
                                    //for 8byte FEA --> end

                                    length1 = result4.length()+result6.length()+result8.length();
                                    length2 = result5.length()+result7.length()+result9.length();

                                    Log.d("plaintext : ", result3+" "+result3.length());
                                    Toast.makeText(getApplicationContext(), "plaintext ; " + result + ", "+result.length()+ "\nciphertext : " +
                                                    result2 + ", "+result2.length()+ "\nrecovery : "+
                                                    result3+ ", "+result3.length() + "\nAES 128 ciphertext : " + aesresult+aesresult2+ ", "+length3 +
                                                    "\nFEA_ciphertext : " + result4+result6+result8 +", "+ length1 +
                                                    "\nFEA_recovery : "+ result5+result7+result9 +", "+ length2
                                            , Toast.LENGTH_SHORT).show();
                                }
                                else if(result.length() == 24){
                                    KSTS("a");

                                    reminder = result.substring(0,16);
                                    reminder2 = result.substring(16);

                                    aesresult=aesenc(reminder,reminder.length());
                                    Log.d("aes ciphertext : ", aesresult+" "+aesresult.length());
                                    aesresult2 = aesenc(reminder2,reminder2.length());
                                    Log.d("aes ciphertext : ", aesresult2+" "+aesresult2.length());
                                    length3 = aesresult.length()+aesresult2.length();

                                    split8 = result.substring(0,8);
                                    split4 = result.substring(8,16);
                                    split8_1 = result.substring(16);

                                    //for 8byte FEA --> start
                                    result4 = tbcenc(split8); // for FEA Encryption
                                    Log.d("FEA_enc", result4+",  "+ result4.length());
                                    result5 = tbcdec(result4, result4.length());        // for FEA Decryption
                                    result5 = result5.substring(0,8);
                                    Log.d("FEA_dec", result5 +",  "+ result5.length());
                                    result4 = result4.substring(0,8);
                                    //for 8byte FEA --> end

                                    //for 8byte FEA --> start
                                    result6 = tbcenc(split4);
                                    result7 = tbcdec(result6, result6.length());
                                    result7 = result7.substring(0,8);
                                    result6 = result6.substring(0,8);
                                    //for 8byte FEA --> end

                                    //for 8byte FEA --> start
                                    result8 = tbcenc(split8_1);
                                    result9 = tbcdec(result8, result8.length());
                                    result9 = result9.substring(0,8);
                                    result8 = result8.substring(0,8);
                                    //for 8byte FEA --> end

                                    length1 = result4.length()+result6.length()+result8.length();
                                    length2 = result5.length()+result7.length()+result9.length();

                                    Log.d("plaintext : ", result3+" "+result3.length());
                                    Toast.makeText(getApplicationContext(), "plaintext ; " + result + ", "+result.length()+ "\nciphertext : " +
                                                    result2 + ", "+result2.length()+ "\nrecovery : "+
                                                    result3+ ", "+result3.length() + "\nAES 128 ciphertext : " + aesresult+aesresult2+ ", "+length3 +
                                                    "\nFEA_ciphertext : " + result4+result6+result8 +", "+ length1 +
                                                    "\nFEA_recovery : "+ result5+result7+result9 +", "+ length2
                                            , Toast.LENGTH_SHORT).show();

                                }
                                else if(result.length() == 28){
                                    KSTS("a");

                                    reminder = result.substring(0,16);
                                    reminder2 = result.substring(16);

                                    aesresult=aesenc(reminder,reminder.length());
                                    Log.d("aes ciphertext : ", aesresult+" "+aesresult.length());
                                    aesresult2 = aesenc(reminder2,reminder2.length());
                                    Log.d("aes ciphertext : ", aesresult2+" "+aesresult2.length());
                                    length3 = aesresult.length()+aesresult2.length();

                                    split8 = result.substring(0,8);
                                    split4 = result.substring(8,16);
                                    split8_1 = result.substring(16,24);
                                    split4_1 = result.substring(24);

                                    //for 8byte FEA --> start
                                    result4 = tbcenc(split8); // for FEA Encryption
                                    Log.d("FEA_enc", result4+",  "+ result4.length());
                                    result5 = tbcdec(result4, result4.length());        // for FEA Decryption
                                    result5 = result5.substring(0,8);
                                    Log.d("FEA_dec", result5 +",  "+ result5.length());
                                    result4 = result4.substring(0,8);
                                    //for 8byte FEA --> end

                                    //for 8byte FEA --> start
                                    result6 = tbcenc(split4);
                                    result7 = tbcdec(result6, result6.length());
                                    result7 = result7.substring(0,8);
                                    result6 = result6.substring(0,8);
                                    //for 8byte FEA --> end

                                    //for 8byte FEA --> start
                                    result8 = tbcenc(split8_1);
                                    result9 = tbcdec(result8, result8.length());
                                    result9 = result9.substring(0,8);
                                    result8 = result8.substring(0,8);
                                    //for 8byte FEA --> end

                                    //for 4byte FEA --> start
                                    result10 = tbcenc4(split4_1);
                                    result11 = tbcdec4(result10, result10.length());
                                    result11 = result11.substring(0,4);
                                    result10 = result10.substring(0,4);
                                    //for 4byte FEA --> end

                                    length1 = result4.length()+result6.length()+result8.length()+result10.length();
                                    length2 = result5.length()+result7.length()+result9.length()+result11.length();

                                    Log.d("plaintext : ", result3+" "+result3.length());
                                    Toast.makeText(getApplicationContext(), "plaintext ; " + result + ", "+result.length()+ "\nciphertext : " +
                                                    result2 + ", "+result2.length()+ "\nrecovery : "+
                                                    result3+ ", "+result3.length() + "\nAES 128 ciphertext : " + aesresult+aesresult2+ ", "+length3 +
                                                    "\nFEA_ciphertext : " + result4+result6+result8+result10 +", "+ length1 +
                                                    "\nFEA_recovery : "+ result5+result7+result9+result11 +", "+ length2
                                            , Toast.LENGTH_SHORT).show();

                                }
                                else if(result.length() == 32){
                                    KSTS("a");

                                    reminder = result.substring(0,16);
                                    reminder2 = result.substring(16);

                                    aesresult=aesenc(reminder,reminder.length());
                                    Log.d("aes ciphertext : ", aesresult+" "+aesresult.length());
                                    aesresult2 = aesenc(reminder2,reminder2.length());
                                    Log.d("aes ciphertext : ", aesresult2+" "+aesresult2.length());
                                    length3 = aesresult.length()+aesresult2.length();

                                    split8 = result.substring(0,8);
                                    split4 = result.substring(8,16);
                                    split8_1 = result.substring(16,24);
                                    split4_1 = result.substring(24);

                                    //for 8byte FEA --> start
                                    result4 = tbcenc(split8); // for FEA Encryption
                                    Log.d("FEA_enc", result4+",  "+ result4.length());
                                    result5 = tbcdec(result4, result4.length());        // for FEA Decryption
                                    result5 = result5.substring(0,8);
                                    Log.d("FEA_dec", result5 +",  "+ result5.length());
                                    result4 = result4.substring(0,8);
                                    //for 8byte FEA --> end

                                    //for 8byte FEA --> start
                                    result6 = tbcenc(split4);
                                    result7 = tbcdec(result6, result6.length());
                                    result7 = result7.substring(0,8);
                                    result6 = result6.substring(0,8);
                                    //for 8byte FEA --> end

                                    //for 8byte FEA --> start
                                    result8 = tbcenc(split8_1);
                                    result9 = tbcdec(result8, result8.length());
                                    result9 = result9.substring(0,8);
                                    result8 = result8.substring(0,8);
                                    //for 8byte FEA --> end

                                    //for 8byte FEA --> start
                                    result10 = tbcenc(split4_1);
                                    result11 = tbcdec(result10, result10.length());
                                    result11 = result11.substring(0,8);
                                    result10 = result10.substring(0,8);
                                    //for 8byte FEA --> end

                                    length1 = result4.length()+result6.length()+result8.length()+result10.length();
                                    length2 = result5.length()+result7.length()+result9.length()+result11.length();

                                    Log.d("plaintext : ", result3+" "+result3.length());
                                    Toast.makeText(getApplicationContext(), "plaintext ; " + result + ", "+result.length()+ "\nciphertext : " +
                                                    result2 + ", "+result2.length()+ "\nrecovery : "+
                                                    result3+ ", "+result3.length() + "\nAES 128 ciphertext : " + aesresult+aesresult2+ ", "+length3 +
                                                    "\nFEA_ciphertext : " + result4+result6+result8+result10 +", "+ length1 +
                                                    "\nFEA_recovery : "+ result5+result7+result9+result11 +", "+ length2
                                            , Toast.LENGTH_SHORT).show();
                                }
                                else if(result.length() == 4){
                                    KSTS("a");

                                    aesresult=aesenc(result,result.length());
                                    Log.d("aes ciphertext : ", aesresult+" "+aesresult.length());

                                    result4 = tbcenc4(result);
                                    result5 = tbcdec4(result4, result4.length());
                                    result5 = result5.substring(0,4);
                                    result4 = result4.substring(0,4);

                                    Toast.makeText(getApplicationContext(), "plaintext ; " + result + ", "+result.length()+ "\nciphertext : " +
                                                    result2 + ", "+result2.length()+ "\nrecovery : "+
                                                    result3+ ", "+result3.length() + "\nAES 128 ciphertext : " + aesresult+ ", "+aesresult.length() +
                                                    "\nFEA_ciphertext : " + result4+", "+ result4.length() +
                                                    "\nFEA_recovery : "+ result5 +", "+ result5.length()
                                            , Toast.LENGTH_SHORT).show();
                                }



/*
                                int[] num = new int[12];
                                for(int i=0; i<12; i++){
                                    //num[i] = result5.charAt(i);
                                    num[i] = FEA_result_dec.charAt(i);
                                }
                                BigInteger total = new BigInteger("0");
                                BigInteger mul = new BigInteger("1");
                                for(int i=0; i<12; i++){
                                    total = total.add(mul.multiply(BigInteger.valueOf(num[11-i])));
                                    mul = mul.multiply(BigInteger.valueOf(256));
                                }
*/





                                sw = 0;
                                sum = 0;
                                result = "";
                                result2 = "";
                                result3 = "";
                                result4 = ""; //FEA_8_enc
                                result5 = ""; //FEA_8_dec
                                split8 = "";
                                split4 = "";
                                split8_1 = "";
                                split4_1 = "";
                                result6 = ""; // for FEA_4 Decryption
                                result7 = ""; // for FEA_4 Decryption
                                result8 = "";
                                result9 = "";
                                result10 = "";
                                result11 = "";
                                aesresult = "";
                                aesresult2 = "";
                                reminder="";
                                reminder2="";
                                length1 = 0;
                                length2 = 0;
                                length3=0;
                                return false;
                            }
                            if (deltaY > 0) {
                                Log.i(logTag, "Swipe Bottom to Top");       // All clear
                                mSwipeDetected = Action.BT;

                                sw = 0;
                                sum = 0;
                                result = "";
                                result2 = "";
                                result3 = "";
                                result4 = "";
                                result5 = "";
                                split8 = "";
                                split4 = "";
                                split8_1 = "";
                                split4_1 = "";
                                result6 = ""; // for FEA_4 Decryption
                                result7 = ""; // for FEA_4 Decryption
                                result8 = "";
                                result9 = "";
                                result10 = "";
                                result11 = "";
                                aesresult = "";
                                aesresult2 = "";
                                reminder="";
                                reminder2="";
                                length1 = 0;
                                length2 = 0;
                                length3=0;
                                return false;
                            }
                        }
                    }
                }
                if ((X / 2 - 102) > curX && rtop < curY && rtop + Y_R - 51 > curY) {
                    Log.d("Layout", "1");
                    in = 1;
                    vibrator.vibrate(10);
                }
                if ((X / 2 - 102) > curX && rtop + Y_R + 51 < curY && rtop + Y_R * 2 - 51 > curY) {
                    Log.d("Layout", "2");
                    in = 2;
                    vibrator.vibrate(10);
                }
                if ((X / 2 - 102) > curX && rtop + Y_R * 2 + 51 < curY && rtop + Y_R * 3 - 51 > curY) {
                    Log.d("Layout", "3");
                    in = 4;
                    vibrator.vibrate(10);
                }
                if ((X / 2 + 102) < curX && rtop < curY && rtop + Y_R - 51 > curY) {
                    Log.d("Layout", "4");
                    in = 8;
                    vibrator.vibrate(10);
                }
                if ((X / 2 + 102) < curX && rtop + Y_R + 51 < curY && rtop + Y_R * 2 - 51 > curY) {
                    Log.d("Layout", "5");
                    in = 16;
                    vibrator.vibrate(10);
                }
                if ((X / 2 + 102) < curX && rtop + Y_R * 2 + 51 < curY && rtop + Y_R * 3 - 51 > curY) {
                    Log.d("Layout", "6");
                    in = 32;
                    vibrator.vibrate(10);
                }
            }
            if(event.getAction() == MotionEvent.ACTION_UP) {
                AUX = event.getRawX();
                AUY = event.getRawY();
                //Log.d("dd", "ACTION_UP");
                if (swipeDetected()){
                    //스와이프 처리
                    Log.d("dd", "ddddddd");
                    mSwipeDetected = Action.None;
                    return false;
                }
                /*if (b1==0 && (X / 2 - 102) > AUX && rtop < AUY && rtop + Y_R - 51 > AUY) {
                    b1 = 1;
                }
                if (b2==0 && (X / 2 - 102) > AUX && rtop + Y_R + 51 < AUY && rtop + Y_R * 2 - 51 > AUY) {

                    b2 = 1;
                }
                if (b3==0 && (X / 2 - 102) > AUX && rtop + Y_R * 2 + 51 < AUY && rtop + Y_R * 3 - 51 > AUY) {

                    b3 = 1;
                }
                if (b4==0 && (X / 2 + 102) < AUX && rtop < AUY && rtop + Y_R - 51 > AUY) {

                    b4 = 1;
                }
                if (b5==0 && (X / 2 + 102) < AUX && rtop + Y_R + 51 < AUY && rtop + Y_R * 2 - 51 > AUY) {

                    b5 = 1;
                }
                if (b6==0 && (X / 2 + 102) < AUX && rtop + Y_R * 2 + 51 < AUY && rtop + Y_R * 3 - 51 > AUY) {

                    b6 = 1;
                }*/
                if(b1==0&&in==1)
                {
                    b1 = 1;
                    sum += in;
                }
                else if(b2==0&&in==2){
                    b2 = 1;
                    sum += in;
                }
                else if(b3==0&&in==4){
                    b3 = 1;
                    sum += in;
                }
                else if(b4==0&&in==8){
                    b4 = 1;
                    sum += in;
                }
                else if(b5==0&&in==16){
                    b5 = 1;
                    sum += in;
                }
                else if(b6==0&&in==32){
                    b6 = 1;
                    sum += in;
                }
                in = 0;
                Log.d("sum : ", String.valueOf(sum));
            }
            return true;
        }
    };
}
