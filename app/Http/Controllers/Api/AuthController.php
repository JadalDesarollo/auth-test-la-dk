<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Exception;
use App\Helpers\Helpers;

class AuthController extends Controller
{
    /**
     * User login API method
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email'    => 'required|email',
            'password' => 'required'
        ]);

        if ($validator->fails()) return sendError('Validation Error.', $validator->errors(), 422);

        $credentials = $request->only('email', 'password');

        if (Auth::attempt($credentials)) {
            $user             = Auth::user();
            $success['name']  = $user->name;
            $success['token'] = $user->createToken('accessToken')->accessToken;
            $success['rol'] = $user->getRoleNames()->toArray();
            $success['permissions'] = $user->getPermissionsViaRoles()->pluck('name')->toArray();

            return sendResponse($success, 'You are successfully logged in.');
        } else {
            return sendError('Unauthorised', ['error' => 'Unauthorised'], 401);
        }
    }

    /**
     * User registration API method
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name'     => 'required',
            'email'    => 'required|email|unique:users',
            'password' => 'required|min:8'
        ]);

        if ($validator->fails()) return sendError('Validation Error.', $validator->errors(), 422);

        try {
            $user = User::create([
                'name'     => $request->name,
                'email'    => $request->email,
                'password' => bcrypt($request->password)
            ]);

            $success['name']  = $user->name;
            $message          = 'Yay! A user has been successfully created.';
            $success['token'] = $user->createToken('accessToken')->accessToken;
        } catch (Exception $e) {
            $success['token'] = [];
            $message          = 'Oops! Unable to create a new user.';
        }

        return sendResponse($success, $message);
    }

    /**
     * This method returns authenticated user details
     */
    public function me()
    {
        if (auth()->user()) {
            return response()->json(['authenticated-user' => auth()->user()], 200);
        } else {
            return sendError('Unauthorised', ['error' => 'Unauthorised'], 401);
        }
    }

    public function logout(Request $request)
    {
        auth()->user()->token()->revoke();
        return response()->json(['message' => 'Successfully logged out.']);
    }

    public function index()
    {
        try {
            $users = User::with('roles')->get();
            return sendResponse('Success', $users);
        } catch (Exception $e) {
            return sendError($e->getMessage(), $e->getCode());
        }
    }

    public function show($id)
    {
        $user = User::find($id);

        if ($user)
            return sendResponse('Success', $user);
        else
            return sendError('Data not found');
    }
}
