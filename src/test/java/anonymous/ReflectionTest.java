package anonymous;

import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;

public class ReflectionTest {

    @Test
    public void reflectionTest() throws ClassNotFoundException {
        for (var method : TestClass.class.getDeclaredMethods()) {
            System.out.println(String.format("Discovered method %s", method));
            try {
                method.invoke(new TestClass(), new TestClass());
            } catch (IllegalAccessException | InvocationTargetException | IllegalArgumentException e) {
                e.printStackTrace();
            }
        }

        Object object = new TestClass();
        System.out.println(object.getClass());
        System.out.println(Class.forName(object.getClass().getName()));
    }

    class TestClass {

        void methodOne() {}

        void methodTwo(TestClass arg) {
            System.out.println(String.format("Argument: %s", arg));
        }
    }
}
