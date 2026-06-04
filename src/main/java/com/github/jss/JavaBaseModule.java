package com.github.jss;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import sun.misc.Unsafe;

@SuppressWarnings("removal")
final class JavaBaseModule {

    private static final long VISIBLE_OFFSET = 12;
    private static final Module JAVA_BASE = ModuleLayer.boot().findModule("java.base").get();

    private static final Method ADD_EXPORTS;
    static {
        Method addExports = null;
        try {
            Field theUnsafe = Unsafe.class.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            Unsafe unsafe = (Unsafe) theUnsafe.get(null);

            addExports = Module.class.getDeclaredMethod("implAddExports", String.class, Module.class);
            unsafe.putBoolean(addExports, VISIBLE_OFFSET, true);
        } catch (NoSuchMethodException | SecurityException | NoSuchFieldException | IllegalArgumentException
                | IllegalAccessException e) {
            throw new RuntimeException(e);
        } finally {
            ADD_EXPORTS = addExports;
        }
    }

    static void addExports(String packageName) {
        try {
            ADD_EXPORTS.invoke(JAVA_BASE, packageName, JavaBaseModule.class.getModule());
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    static Class<?> getClass(String name) {
        return Class.forName(JAVA_BASE, name);
    }

}
