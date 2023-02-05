package com.mi.car.jsse.easysec.jsse.provider;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;

/* access modifiers changed from: package-private */
public class ReflectionUtil {
    ReflectionUtil() {
    }

    static Method findMethod(Method[] methods, String name) {
        if (methods != null) {
            for (Method m : methods) {
                if (m.getName().equals(name)) {
                    return m;
                }
            }
        }
        return null;
    }

    static boolean hasMethod(Method[] methods, String name) {
        return findMethod(methods, name) != null;
    }

    static Class<?> getClass(final String className) {
        if (className == null) {
            return null;
        }
        return (Class) AccessController.doPrivileged(new PrivilegedAction<Class<?>>() {
            /* class com.mi.car.jsse.easysec.jsse.provider.ReflectionUtil.AnonymousClass1 */

            @Override // java.security.PrivilegedAction
            public Class<?> run() {
                try {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    if (classLoader == null) {
                        return Class.forName(className);
                    }
                    return classLoader.loadClass(className);
                } catch (Exception e) {
                    return null;
                }
            }
        });
    }

    static <T> Constructor<T> getDeclaredConstructor(final String className, final Class<?>... parameterTypes) {
        if (className == null) {
            return null;
        }
        return (Constructor) AccessController.doPrivileged(new PrivilegedAction<Constructor<T>>() {
            /* class com.mi.car.jsse.easysec.jsse.provider.ReflectionUtil.AnonymousClass2 */

            @Override // java.security.PrivilegedAction
            public Constructor<T> run() {
                Class<?> loadClass;
                try {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    if (classLoader == null) {
                        loadClass = Class.forName(className);
                    } else {
                        loadClass = classLoader.loadClass(className);
                    }
                    if (loadClass != null) {
                        return (Constructor<T>) loadClass.getDeclaredConstructor(parameterTypes);
                    }
                } catch (Exception e) {
                }
                return null;
            }
        });
    }

    static Method getMethod(final String className, final String methodName, final Class<?>... parameterTypes) {
        if (className == null || methodName == null) {
            return null;
        }
        return (Method) AccessController.doPrivileged(new PrivilegedAction<Method>() {
            /* class com.mi.car.jsse.easysec.jsse.provider.ReflectionUtil.AnonymousClass3 */

            @Override // java.security.PrivilegedAction
            public Method run() {
                Class<?> clazz;
                try {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    if (classLoader == null) {
                        clazz = Class.forName(className);
                    } else {
                        clazz = classLoader.loadClass(className);
                    }
                    if (clazz != null) {
                        return clazz.getMethod(methodName, parameterTypes);
                    }
                } catch (Exception e) {
                }
                return null;
            }
        });
    }

    static Method[] getMethods(final String className) {
        if (className == null) {
            return null;
        }
        return (Method[]) AccessController.doPrivileged(new PrivilegedAction<Method[]>() {
            /* class com.mi.car.jsse.easysec.jsse.provider.ReflectionUtil.AnonymousClass4 */

            @Override // java.security.PrivilegedAction
            public Method[] run() {
                Class<?> clazz;
                try {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    if (classLoader == null) {
                        clazz = Class.forName(className);
                    } else {
                        clazz = classLoader.loadClass(className);
                    }
                    if (clazz != null) {
                        return clazz.getMethods();
                    }
                } catch (Exception e) {
                }
                return null;
            }
        });
    }

    static Integer getStaticInt(final String className, final String fieldName) {
        return (Integer) AccessController.doPrivileged(new PrivilegedAction<Integer>() {
            /* class com.mi.car.jsse.easysec.jsse.provider.ReflectionUtil.AnonymousClass5 */

            @Override // java.security.PrivilegedAction
            public Integer run() {
                Class<?> clazz;
                Field field;
                try {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    if (classLoader == null) {
                        clazz = Class.forName(className);
                    } else {
                        clazz = classLoader.loadClass(className);
                    }
                    if (clazz == null || (field = clazz.getField(fieldName)) == null || Integer.TYPE != field.getType()) {
                        return null;
                    }
                    return Integer.valueOf(field.getInt(null));
                } catch (Exception e) {
                    return null;
                }
            }
        });
    }

    static Integer getStaticIntOrDefault(String className, String fieldName, int defaultValue) {
        Integer value = getStaticInt(className, fieldName);
        if (value != null) {
            defaultValue = value.intValue();
        }
        return Integer.valueOf(defaultValue);
    }

    static Object invokeGetter(Object obj, Method method) {
        return invokeMethod(obj, method, new Object[0]);
    }

    static Object invokeMethod(final Object obj, final Method method, final Object... args) {
        return AccessController.doPrivileged(new PrivilegedAction<Object>() {
            /* class com.mi.car.jsse.easysec.jsse.provider.ReflectionUtil.AnonymousClass6 */

            @Override // java.security.PrivilegedAction
            public Object run() {
                try {
                    return method.invoke(obj, args);
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                } catch (InvocationTargetException e2) {
                    throw new RuntimeException(e2);
                }
            }
        });
    }

    static void invokeSetter(Object obj, Method method, Object arg) {
        invokeMethod(obj, method, arg);
    }
}
