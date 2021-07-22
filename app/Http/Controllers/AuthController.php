<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\User;
use App\SessionUser;
use Validator;
use Auth;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\DB;



class AuthController extends Controller
{
    
    
     /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','register','getUser']]);
    }

    public function getUser(){
        
        $user = User::all()->where('level','<=',2);      
        return $user;
        
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        //Xác thực user có tk chưa
        $credentials = $request->only('email','password');

        if (Auth::attempt($credentials)) { 
            
            $checkTokenExit = SessionUser::where('user_id', auth()->id())->first();

            if(empty($checkTokenExit)){
                 // Authentication passed...
                $userSession=SessionUser::create([
                'token'=>Str::random(40),
                'refresh_token'=>Str::random(40),
                'token_expried'=>date('Y-m-d H:i:s', strtotime('+30 day')),
                'refresh_token_expried'=>date('Y-m-d H:i:s', strtotime('+360 day')),
                'user_id'=>auth()->id(),
            ]);
            }else{
                $userSession = $checkTokenExit;
            }

            $request->session()->put('data', Auth::user());
            $userss= $request->session()->get('data');
            return User::all()->where('level','<=',$userss['level']);
             
        } else {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request) {
        $request->validate([
            'name'=>'required',
            'email'=>'required',
            'password'=>'required',
            'level'=>'required',
        ]);

        $user = User::create([
            'name'=> $request->name,
            'email'=>$request->email,
            'password'=>bcrypt($request->password),
            'level'=>$request->level,
        ]);
        $user->save();
        return response()->json(['code'=> 201 , 'data'=>$user],201);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'user' => auth()->user()
            
        ]);
    }

}
