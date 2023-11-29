<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;
use Illuminate\Support\Facades\Validator;
use Exception;
use Illuminate\Validation\ValidationException;

class PermissionsController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $permissions = Permission::all();
        return sendResponse('Success', $permissions);
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|unique:users,name'
        ]);

        if ($validator->fails()) return sendError('Validation Error.', $validator->errors(), 422);

        try {
            $permission = Permission::create([
                'name' => $request->name,
            ]);
            return sendResponse('Permission create success!', $permission);
        } catch (Exception $e) {
            return sendError($e->getMessage(), $e->getCode());
        }

        Permission::create($request->only('name'));

        return sendResponse('Rol create success!', $request);
    }

    /**
     * Display the specified resource.
     */
    public function show(Permission $permission)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        try {
            $permission = Permission::findOrFail($id); 
            $validator = Validator::make($request->all(), [
                'name' => 'required|unique:permissions,name,' . $permission->id, 
            ]);
    
            if ($validator->fails()) {
                throw new ValidationException($validator); 
            }
    
            $permission->update([
                'name' => $request->input('name'), 
            ]);
        
            return sendResponse('Permission update success!', $permission);
        } catch (ValidationException $e) {
            return sendError('Validation Error.', $e->errors(), 422);
        } catch (Exception $e) {
            return sendError($e->getMessage(), $e->getCode());
        }
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy($id)
    {
            $permission = Permission::find($id);
    
            if (!$permission) {
                return response()->json(['success' => false, 'message' => 'Permission not found.'], 404);
            }
    
            $permission->delete();
    
            return response()->json(['success' => true, 'message' => 'Permission deleted successfully.']);
    }
}
