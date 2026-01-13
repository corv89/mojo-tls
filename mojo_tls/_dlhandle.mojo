"""Dynamic library loading wrapper.

This module provides a DLHandle struct for loading dynamic libraries
and calling functions from them, similar to the old sys.ffi.DLHandle.

Uses POSIX dlopen/dlsym/dlclose directly via external_call.
"""

from sys.ffi import external_call, c_int, c_char


# POSIX dlopen flags
alias RTLD_LAZY: c_int = 1
alias RTLD_NOW: c_int = 2
alias RTLD_LOCAL: c_int = 4
alias RTLD_GLOBAL: c_int = 8


struct DLHandle:
    """Handle to a dynamically loaded library.

    Provides functionality to load dynamic libraries and call functions
    from them. The library is automatically closed when the handle is
    destroyed.

    Example:
        var lib = DLHandle("/path/to/libfoo.dylib")
        var result = lib.call["some_function", Int](arg1, arg2)
    """

    var _handle: Int

    fn __init__(out self, path: String) raises:
        """Load a dynamic library.

        Args:
            path: Path to the library file.

        Raises:
            If the library cannot be loaded.
        """
        # Ensure null-terminated string
        var path_null = path + "\0"
        var path_ptr = path_null.unsafe_ptr()

        self._handle = external_call["dlopen", Int](path_ptr, RTLD_NOW)
        if self._handle == 0:
            # Get error message
            var err = external_call["dlerror", Int]()
            raise Error("Failed to load library: " + path)

    fn __del__(owned self):
        """Close the library handle."""
        if self._handle != 0:
            _ = external_call["dlclose", c_int](self._handle)

    fn __moveinit__(out self, owned other: Self):
        """Move constructor."""
        self._handle = other._handle
        other._handle = 0

    fn get_symbol(self, name: String) -> Int:
        """Get a symbol address from the library.

        Args:
            name: Name of the symbol.

        Returns:
            Address of the symbol, or 0 if not found.
        """
        var name_null = name + "\0"
        var name_ptr = name_null.unsafe_ptr()
        return external_call["dlsym", Int](self._handle, name_ptr)

    fn call[
        name: StringLiteral,
        return_type: AnyType,
    ](self) -> return_type:
        """Call a function with no arguments.

        Parameters:
            name: Name of the function.
            return_type: Return type of the function.

        Returns:
            The function's return value.
        """
        return external_call[name, return_type]()

    fn call[
        name: StringLiteral,
        return_type: AnyType,
        T0: AnyType,
    ](self, arg0: T0) -> return_type:
        """Call a function with one argument."""
        return external_call[name, return_type](arg0)

    fn call[
        name: StringLiteral,
        return_type: AnyType,
        T0: AnyType,
        T1: AnyType,
    ](self, arg0: T0, arg1: T1) -> return_type:
        """Call a function with two arguments."""
        return external_call[name, return_type](arg0, arg1)

    fn call[
        name: StringLiteral,
        return_type: AnyType,
        T0: AnyType,
        T1: AnyType,
        T2: AnyType,
    ](self, arg0: T0, arg1: T1, arg2: T2) -> return_type:
        """Call a function with three arguments."""
        return external_call[name, return_type](arg0, arg1, arg2)

    fn call[
        name: StringLiteral,
        return_type: AnyType,
        T0: AnyType,
        T1: AnyType,
        T2: AnyType,
        T3: AnyType,
    ](self, arg0: T0, arg1: T1, arg2: T2, arg3: T3) -> return_type:
        """Call a function with four arguments."""
        return external_call[name, return_type](arg0, arg1, arg2, arg3)

    fn call[
        name: StringLiteral,
        return_type: AnyType,
        T0: AnyType,
        T1: AnyType,
        T2: AnyType,
        T3: AnyType,
        T4: AnyType,
    ](self, arg0: T0, arg1: T1, arg2: T2, arg3: T3, arg4: T4) -> return_type:
        """Call a function with five arguments."""
        return external_call[name, return_type](arg0, arg1, arg2, arg3, arg4)

    fn get_function[T: AnyType](self, name: String) -> Int:
        """Get a function pointer from the library.

        Parameters:
            T: The expected function signature type (unused, for API compat).

        Args:
            name: Name of the function.

        Returns:
            Function pointer address, or 0 if not found.
        """
        return self.get_symbol(name)
