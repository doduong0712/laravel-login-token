<?php

namespace App\Http\Controllers;

use Illuminate\Support\Str;
use Illuminate\Http\Request;
//use Illuminate\Support\Facades\DB;
use App\SessionUser;
use Auth;

class LoginController extends Controller
{
    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        //Xác thực user có tk chưa
        $credentials = $request->only('email', 'password');

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

            /* return  Auth::user('userSession')->select('level')->get(); */
             
            return $userSession;
           /*  $user = response()->json([$userSession])['level'];
            foreach ($user as $value){
                return $user;
            } */
/*  
            $users = DB::table('users')->select('name')->get();
            return $users; */

            //return response()->json(['expires_in' => auth()->factory()->getTTL() * 60,'access_token' => $token,'token_type' => 'bearer','user' => auth()->user()]);
          
        } else {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }
}
