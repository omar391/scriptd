import android.accounts.Account;
import android.app.Application;
import android.app.Instrumentation;
import android.content.Context;
import android.os.Looper;

import java.lang.reflect.Method;

public final class MiwatchCollector {
    private static Object invoke(Object target, String name, Class<?>[] types, Object... args)
            throws Exception {
        Method method = target.getClass().getMethod(name, types);
        return method.invoke(target, args);
    }

    public static void main(String[] args) throws Exception {
        Looper.prepareMainLooper();
        Class<?> activityThread = Class.forName("android.app.ActivityThread");
        Object thread = activityThread.getMethod("systemMain").invoke(null);
        Context systemContext = (Context) activityThread
                .getMethod("getSystemContext")
                .invoke(thread);
        Context appContext = systemContext.createPackageContext(
                "com.xiaomi.router",
                Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_IGNORE_SECURITY);
        ClassLoader appLoader = appContext.getClassLoader();

        Application application = new Instrumentation().newApplication(
                CollectorApplication.class, appContext);
        Class<?> managerClass = Class.forName(
                "com.xiaomi.passport.accountmanager.MiAccountManager", true, appLoader);
        Object manager = managerClass.getMethod("get", Context.class).invoke(null, application);
        Account account = (Account) managerClass.getMethod("getXiaomiAccount").invoke(manager);
        if (account == null) {
            throw new IllegalStateException("no Xiaomi account is present; complete emulator login first");
        }
        String encryptedUserId = (String) managerClass
                .getMethod("getUserData", Account.class, String.class)
                .invoke(manager, account, "encrypted_user_id");
        String extendedPassToken = (String) managerClass
                .getMethod("getPassword", Account.class)
                .invoke(manager, account);
        if (extendedPassToken == null || extendedPassToken.indexOf(',') < 1) {
            throw new IllegalStateException("Xiaomi account has no usable pass token");
        }
        String passToken = extendedPassToken.substring(0, extendedPassToken.indexOf(','));
        Object serviceFuture = managerClass
                .getMethod("getServiceToken", Context.class, String.class)
                .invoke(manager, application, "xiaoqiang");
        Object serviceResult = invoke(serviceFuture, "get", new Class<?>[0]);
        Class<?> serviceResultClass = serviceResult.getClass();
        Object errorCode = serviceResultClass.getField("errorCode").get(serviceResult);
        if (errorCode == null || !"ERROR_NONE".equals(errorCode.toString())) {
            throw new IllegalStateException("Xiaomi service credential is unavailable: " + errorCode);
        }
        String serviceToken = (String) serviceResultClass.getField("serviceToken").get(serviceResult);
        String ssecurity = (String) serviceResultClass.getField("security").get(serviceResult);
        if (serviceToken == null || serviceToken.length() == 0 || ssecurity == null || ssecurity.length() == 0) {
            throw new IllegalStateException("Xiaomi service credential is incomplete");
        }
        System.out.print("{\"access_token\":\"\",\"user_id\":\""
                + json(account.name) + "\",\"c_user_id\":\""
                + json(encryptedUserId) + "\",\"pass_token\":\""
                + json(passToken) + "\",\"service_token\":\""
                + json(serviceToken) + "\",\"ssecurity\":\""
                + json(ssecurity) + "\",\"expires_at\":"
                + (System.currentTimeMillis() / 1000L + 86400L)
                + ",\"cookies\":{\"serviceToken\":\""
                + json(serviceToken) + "\"}}\n");
        System.out.flush();
        System.exit(0);
    }

    private static String json(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    public static final class CollectorApplication extends Application {
        @Override
        public Context getApplicationContext() {
            return this;
        }
    }
}
