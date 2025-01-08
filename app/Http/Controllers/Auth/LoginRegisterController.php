<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class LoginRegisterController extends Controller
{
    public function register()
    {
        return view('auth,register');
    }

    public function store(request $request)
    {
        $request->validate([
            'name' => 'required|string|max:258' ,
            'email' => 'required|email|max:258|unique:user' ,
            'password' => 'required|min:8|cinfirmed' ,
        ]);

        User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'usertype' => 'admin'
        ]);

        $credentials = $request->only('email', 'password');
        Auth::attempt($credentials);
        $request->session()->regenerate();

        if ($request->user()->usertype == 'admin') {
            return redirect('admin/dashboard')->WithSuccess('You have successfully registered & logged in!');
        }
        
        return redirect()->intended(route('dashboard'));
    }

    public function login()
    {
        return view('auth.login');
    }

    public function authenticate(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|email' ,
            'password' => 'required'
        ]);

        if (Auth::attempt($credentials)) {
            $request->session()->regenerate();
            if ($request->user()->usertype == 'admin') {
                return redirect('admin/dashboard')->WithSuccess('You have successfully logged in!');
            }
        }

        return back()->WithErrors([
            'email' => 'You provided credentials do not match in our records.',
        ])->onlyinput('email');     
    }

    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        return redirect()->route('login')
        ->WithSuccess('You have loged out successfully!');;
    }
}
