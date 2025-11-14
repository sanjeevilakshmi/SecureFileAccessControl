import java.io.*;
import java.nio.file.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * SecureFileAccessControl.java
 *
 * Advanced single-file Java program demonstrating:
 *  - PBKDF2 password hashing with salt
 *  - Role-based permissions
 *  - Thread-safe in-memory stores with persistence
 *  - Session tokens
 *  - Audit logging
 *
 * NOTE: This is a demo — in production you would:
 *  - Use a real DB, better serialization format (JSON/DB)
 *  - Use TLS for networked access, not stdout/stdin
 *  - Be careful with plaintext paths and file handling
 */
public class SecureFileAccessControl {

    // --------------------------
    // Config
    // --------------------------
    static final Path DATA_DIR = Paths.get("sfac_data");
    static final Path USERS_FILE = DATA_DIR.resolve("users.ser");
    static final Path FILES_FILE = DATA_DIR.resolve("files.ser");
    static final Path LOGS_FILE  = DATA_DIR.resolve("logs.ser");

    static final int    PBKDF2_ITER = 100_000;
    static final int    SALT_BYTES  = 16;
    static final int    HASH_BYTES  = 32;
    static final long   SESSION_TTL_SECONDS = 30 * 60; // 30 minutes

    // --------------------------
    // Data Models (Serializable)
    // --------------------------
    static class User implements Serializable {
        final String username;
        final byte[] pwdHash; // PBKDF2 hash
        final byte[] salt;
        final String role;

        User(String username, byte[] pwdHash, byte[] salt, String role) {
            this.username = username;
            this.pwdHash = pwdHash;
            this.salt = salt;
            this.role = role;
        }
    }

    static class FileRecord implements Serializable {
        final String filename;
        final String owner;
        final Instant uploadedAt;
        final long sizeBytes;

        FileRecord(String filename, String owner, long sizeBytes) {
            this.filename = filename;
            this.owner = owner;
            this.uploadedAt = Instant.now();
            this.sizeBytes = sizeBytes;
        }
    }

    static class AuditEntry implements Serializable {
        final Instant when;
        final String actor;
        final String action;
        final String target;
        final boolean success;
        final String detail;

        AuditEntry(String actor, String action, String target, boolean success, String detail) {
            this.when = Instant.now();
            this.actor = actor;
            this.action = action;
            this.target = target;
            this.success = success;
            this.detail = detail;
        }

        @Override
        public String toString() {
            String t = DateTimeFormatter.ISO_LOCAL_DATE_TIME.withZone(ZoneId.systemDefault()).format(when);
            return String.format("[%s] %s: %s -> %s (success=%b) %s", t, actor, action, target, success, detail);
        }
    }

    // --------------------------
    // Stores (thread-safe)
    // --------------------------
    static class UserStore {
        private final ConcurrentMap<String, User> users = new ConcurrentHashMap<>();
        private final ReadWriteLock lock = new ReentrantReadWriteLock();

        void put(User u) {
            lock.writeLock().lock();
            try { users.put(u.username, u); } finally { lock.writeLock().unlock(); }
        }
        User get(String username) {
            lock.readLock().lock();
            try { return users.get(username); } finally { lock.readLock().unlock(); }
        }
        Collection<User> list() {
            lock.readLock().lock();
            try { return new ArrayList<>(users.values()); } finally { lock.readLock().unlock(); }
        }
        boolean contains(String username) {
            lock.readLock().lock();
            try { return users.containsKey(username); } finally { lock.readLock().unlock(); }
        }
        void remove(String username) {
            lock.writeLock().lock();
            try { users.remove(username); } finally { lock.writeLock().unlock(); }
        }
        void loadFrom(Path p) throws Exception {
            if (!Files.exists(p)) return;
            try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(p))) {
                Object o = ois.readObject();
                if (o instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, User> map = (Map<String, User>) o;
                    lock.writeLock().lock();
                    try { users.clear(); users.putAll(map); } finally { lock.writeLock().unlock(); }
                }
            }
        }
        void saveTo(Path p) throws Exception {
            Files.createDirectories(p.getParent());
            try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(p))) {
                lock.readLock().lock();
                try { oos.writeObject(new HashMap<>(users)); } finally { lock.readLock().unlock(); }
            }
        }
    }

    static class FileStore {
        private final ConcurrentMap<String, FileRecord> files = new ConcurrentHashMap<>();
        private final ReadWriteLock lock = new ReentrantReadWriteLock();

        void put(FileRecord fr) {
            lock.writeLock().lock();
            try { files.put(fr.filename, fr); } finally { lock.writeLock().unlock(); }
        }
        FileRecord get(String filename) {
            lock.readLock().lock();
            try { return files.get(filename); } finally { lock.readLock().unlock(); }
        }
        Collection<FileRecord> list() {
            lock.readLock().lock();
            try { return new ArrayList<>(files.values()); } finally { lock.readLock().unlock(); }
        }
        boolean contains(String filename) {
            lock.readLock().lock();
            try { return files.containsKey(filename); } finally { lock.readLock().unlock(); }
        }
        void remove(String filename) {
            lock.writeLock().lock();
            try { files.remove(filename); } finally { lock.writeLock().unlock(); }
        }
        void loadFrom(Path p) throws Exception {
            if (!Files.exists(p)) return;
            try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(p))) {
                Object o = ois.readObject();
                if (o instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, FileRecord> map = (Map<String, FileRecord>) o;
                    lock.writeLock().lock();
                    try { files.clear(); files.putAll(map); } finally { lock.writeLock().unlock(); }
                }
            }
        }
        void saveTo(Path p) throws Exception {
            Files.createDirectories(p.getParent());
            try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(p))) {
                lock.readLock().lock();
                try { oos.writeObject(new HashMap<>(files)); } finally { lock.readLock().unlock(); }
            }
        }
    }

    static class AuditStore {
        private final List<AuditEntry> logs = Collections.synchronizedList(new ArrayList<>());

        void log(AuditEntry e) {
            logs.add(e);
        }
        List<AuditEntry> list() {
            synchronized (logs) {
                return new ArrayList<>(logs);
            }
        }
        void loadFrom(Path p) throws Exception {
            if (!Files.exists(p)) return;
            try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(p))) {
                Object o = ois.readObject();
                if (o instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<AuditEntry> list = (List<AuditEntry>) o;
                    synchronized (logs) {
                        logs.clear();
                        logs.addAll(list);
                    }
                }
            }
        }
        void saveTo(Path p) throws Exception {
            Files.createDirectories(p.getParent());
            try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(p))) {
                synchronized (logs) {
                    oos.writeObject(new ArrayList<>(logs));
                }
            }
        }
    }

    // --------------------------
    // Auth & Access Control
    // --------------------------
    static class Session {
        final String token;
        final String username;
        final Instant created;
        Instant expires;

        Session(String username) {
            this.username = username;
            this.token = UUID.randomUUID().toString();
            this.created = Instant.now();
            this.expires = created.plusSeconds(SESSION_TTL_SECONDS);
        }

        boolean isExpired() { return Instant.now().isAfter(expires); }

        void refresh() { this.expires = Instant.now().plusSeconds(SESSION_TTL_SECONDS); }
    }

    static class AuthService {
        private final UserStore users;
        private final ConcurrentMap<String, Session> sessions = new ConcurrentHashMap<>();

        AuthService(UserStore users) { this.users = users; }

        Session login(String uname, String password) throws Exception {
            User u = users.get(uname);
            if (u == null) return null;
            byte[] hash = pbkdf2(password.toCharArray(), u.salt, PBKDF2_ITER, HASH_BYTES);
            if (Arrays.equals(hash, u.pwdHash)) {
                Session s = new Session(uname);
                sessions.put(s.token, s);
                return s;
            }
            return null;
        }

        void logout(String token) { sessions.remove(token); }

        Session getSession(String token) {
            Session s = sessions.get(token);
            if (s == null) return null;
            if (s.isExpired()) {
                sessions.remove(token);
                return null;
            }
            s.refresh();
            return s;
        }

        void garbageCollectExpired() {
            for (Map.Entry<String, Session> e : sessions.entrySet()) {
                if (e.getValue().isExpired()) sessions.remove(e.getKey());
            }
        }
    }

    static class AccessControl {
        // Simple RBAC map: role -> allowed actions
        private final Map<String, Set<String>> rolePerms = new HashMap<>();

        AccessControl() {
            // define operations: VIEW, UPLOAD, DELETE, LIST_USERS
            rolePerms.put("ADMIN", new HashSet<>(Arrays.asList("VIEW","UPLOAD","DELETE","LIST_USERS")));
            rolePerms.put("MANAGER", new HashSet<>(Arrays.asList("VIEW","UPLOAD")));
            rolePerms.put("EMPLOYEE", new HashSet<>(Collections.singletonList("VIEW")));
        }

        boolean can(String role, String action) {
            Set<String> s = rolePerms.get(role);
            return s != null && s.contains(action);
        }
    }


    // --------------------------
    // Utilities: hashing
    // --------------------------
    static SecureRandom secureRandom = new SecureRandom();

    static byte[] randomSalt() {
        byte[] s = new byte[SALT_BYTES];
        secureRandom.nextBytes(s);
        return s;
    }

    static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }

    // --------------------------
    // Application bootstrap
    // --------------------------
    final UserStore userStore = new UserStore();
    final FileStore fileStore = new FileStore();
    final AuditStore auditStore = new AuditStore();
    final AuthService authService = new AuthService(userStore);
    final AccessControl ac = new AccessControl();

    void ensureData() {
        try {
            Files.createDirectories(DATA_DIR);
            userStore.loadFrom(USERS_FILE);
            fileStore.loadFrom(FILES_FILE);
            auditStore.loadFrom(LOGS_FILE);
        } catch (Exception e) {
            System.err.println("Warning: failed to load persisted data (starting fresh).");
        }

        // create default admin if not present
        if (!userStore.contains("admin")) {
            try {
                byte[] salt = randomSalt();
                byte[] hash = pbkdf2("admin123".toCharArray(), salt, PBKDF2_ITER, HASH_BYTES);
                User admin = new User("admin", hash, salt, "ADMIN");
                userStore.put(admin);
                System.out.println("Created default admin -> username: admin, password: admin123");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    void persistAll() {
        try {
            userStore.saveTo(USERS_FILE);
            fileStore.saveTo(FILES_FILE);
            auditStore.saveTo(LOGS_FILE);
        } catch (Exception e) {
            System.err.println("Failed to persist data: " + e.getMessage());
        }
    }

    // --------------------------
    // CLI / actions
    // --------------------------
    private void runCli() {
        ensureData();
        Scanner sc = new Scanner(System.in);
        ScheduledExecutorService ses = Executors.newSingleThreadScheduledExecutor();
        ses.scheduleAtFixedRate(() -> {
            authService.garbageCollectExpired();
            persistAll();
        }, 1, 60, TimeUnit.SECONDS);

        try {
            while (true) {
                System.out.println("\n=== Secure File Access Control ===");
                System.out.println("1) Login");
                System.out.println("2) Create user (ADMIN only)");
                System.out.println("3) Exit");
                System.out.print("Choice: ");
                String choice = sc.nextLine().trim();
                if (choice.equals("1")) {
                    handleLogin(sc);
                } else if (choice.equals("2")) {
                    System.out.print("Admin token: ");
                    String token = sc.nextLine().trim();
                    Session s = authService.getSession(token);
                    if (s == null) { System.out.println("Invalid/expired token."); continue; }
                    User actor = userStore.get(s.username);
                    if (actor == null || !ac.can(actor.role,"LIST_USERS")) {
                        System.out.println("Access denied.");
                        auditStore.log(new AuditEntry(s.username, "CREATE_USER_ATTEMPT", "-", false, "no permission"));
                        continue;
                    }
                    createUserInteractive(sc, s.username);
                } else if (choice.equals("3")) {
                    System.out.println("Exiting. Saving data...");
                    persistAll();
                    break;
                } else {
                    System.out.println("Invalid choice.");
                }
            }
        } finally {
            ses.shutdownNow();
        }
    }

    private void createUserInteractive(Scanner sc, String actor) {
        try {
            System.out.print("New username: ");
            String u = sc.nextLine().trim();
            if (u.isEmpty() || userStore.contains(u)) { System.out.println("Invalid or exists."); return; }

            System.out.print("Password: ");
            String pw = sc.nextLine();
            System.out.print("Role [ADMIN/MANAGER/EMPLOYEE]: ");
            String role = sc.nextLine().trim().toUpperCase();
            if (!Arrays.asList("ADMIN","MANAGER","EMPLOYEE").contains(role)) {
                System.out.println("Invalid role.");
                return;
            }
            byte[] salt = randomSalt();
            byte[] hash = pbkdf2(pw.toCharArray(), salt, PBKDF2_ITER, HASH_BYTES);
            userStore.put(new User(u, hash, salt, role));
            System.out.println("Created user: " + u + " (" + role + ")");
            auditStore.log(new AuditEntry(actor, "CREATE_USER", u, true, "role=" + role));
        } catch (Exception e) {
            System.out.println("Failed to create user: " + e.getMessage());
            auditStore.log(new AuditEntry(actor, "CREATE_USER", "-", false, e.getMessage()));
        }
    }

    private void handleLogin(Scanner sc) {
        try {
            System.out.print("Username: ");
            String uname = sc.nextLine().trim();
            System.out.print("Password: ");
            String pw = sc.nextLine();
            Session s = authService.login(uname, pw);
            if (s == null) {
                System.out.println("Login failed.");
                auditStore.log(new AuditEntry(uname, "LOGIN", "-", false, "invalid credentials"));
                return;
            }
            System.out.println("Login successful. Session Token: " + s.token);
            auditStore.log(new AuditEntry(uname, "LOGIN", "-", true, "session=" + s.token));
            userMenu(sc, s);
        } catch (Exception e) {
            System.out.println("Login error: " + e.getMessage());
        }
    }

    private void userMenu(Scanner sc, Session s) {
        while (true) {
            Session fresh = authService.getSession(s.token);
            if (fresh == null) { System.out.println("Session expired."); return; }
            User actor = userStore.get(fresh.username);
            System.out.println("\n-- Menu (user: " + actor.username + ", role: " + actor.role + ") --");
            System.out.println("1) View Files");
            if (ac.can(actor.role,"UPLOAD")) System.out.println("2) Upload File");
            if (ac.can(actor.role,"DELETE")) System.out.println("3) Delete File");
            if (ac.can(actor.role,"LIST_USERS")) System.out.println("4) List Users");
            System.out.println("5) View Audit Logs (ADMIN only)");
            System.out.println("0) Logout");
            System.out.print("Choice: ");
            String choice = sc.nextLine().trim();
            if (choice.equals("1")) {
                listFiles(actor.username);
                auditStore.log(new AuditEntry(actor.username, "VIEW_FILES", "-", true, ""));
            } else if (choice.equals("2") && ac.can(actor.role,"UPLOAD")) {
                uploadFileInteractive(sc, actor.username);
            } else if (choice.equals("3") && ac.can(actor.role,"DELETE")) {
                deleteFileInteractive(sc, actor.username);
            } else if (choice.equals("4") && ac.can(actor.role,"LIST_USERS")) {
                listUsers();
            } else if (choice.equals("5")) {
                if (!ac.can(actor.role,"LIST_USERS")) { System.out.println("Access denied."); continue; }
                viewAudit();
            } else if (choice.equals("0")) {
                authService.logout(fresh.token);
                auditStore.log(new AuditEntry(actor.username, "LOGOUT", "-", true, ""));
                System.out.println("Logged out.");
                return;
            } else {
                System.out.println("Invalid choice or no permission.");
            }
        }
    }

    private void uploadFileInteractive(Scanner sc, String actor) {
        System.out.print("Enter local path of file to 'upload' (simulate): ");
        String path = sc.nextLine().trim();
        try {
            Path p = Paths.get(path);
            if (!Files.exists(p) || Files.isDirectory(p)) {
                System.out.println("Local file not found or is a directory.");
                auditStore.log(new AuditEntry(actor, "UPLOAD", path, false, "not found"));
                return;
            }
            String fname = p.getFileName().toString();
            long size = Files.size(p);
            if (fileStore.contains(fname)) {
                System.out.println("A file with that name already exists in the system.");
                auditStore.log(new AuditEntry(actor, "UPLOAD", fname, false, "already exists"));
                return;
            }
            // For demo: we do not copy the file; we register metadata
            fileStore.put(new FileRecord(fname, actor, size));
            System.out.println("Uploaded (metadata) file: " + fname + " (" + size + " bytes)");
            auditStore.log(new AuditEntry(actor, "UPLOAD", fname, true, "size=" + size));
        } catch (Exception e) {
            System.out.println("Upload failed: " + e.getMessage());
            auditStore.log(new AuditEntry(actor, "UPLOAD", path, false, e.getMessage()));
        }
    }

    private void deleteFileInteractive(Scanner sc, String actor) {
        System.out.print("Enter filename to delete: ");
        String fname = sc.nextLine().trim();
        if (!fileStore.contains(fname)) {
            System.out.println("No such file.");
            auditStore.log(new AuditEntry(actor, "DELETE", fname, false, "missing"));
            return;
        }
        FileRecord fr = fileStore.get(fname);
        // Example policy: ADMIN can delete any; MANAGER can delete files they uploaded; employees cannot delete
        User u = userStore.get(actor);
        boolean allowed = false;
        if (u != null && u.role.equals("ADMIN")) allowed = true;
        else if (u != null && u.role.equals("MANAGER") && fr.owner.equals(actor)) allowed = true;

        if (!allowed) {
            System.out.println("Not authorized to delete this file.");
            auditStore.log(new AuditEntry(actor, "DELETE", fname, false, "not authorized"));
            return;
        }
        fileStore.remove(fname);
        System.out.println("Deleted file record: " + fname);
        auditStore.log(new AuditEntry(actor, "DELETE", fname, true, ""));
    }

    private void listFiles(String actor) {
        Collection<FileRecord> list = fileStore.list();
        if (list.isEmpty()) {
            System.out.println("No files.");
            return;
        }
        System.out.println("Files:");
        for (FileRecord fr : list) {
            System.out.printf("- %s (owner=%s, size=%d bytes, uploaded=%s)%n",
                    fr.filename, fr.owner, fr.sizeBytes,
                    DateTimeFormatter.ISO_LOCAL_DATE_TIME.withZone(ZoneId.systemDefault()).format(fr.uploadedAt));
        }
    }

    private void listUsers() {
        Collection<User> list = userStore.list();
        System.out.println("Users:");
        for (User u : list) {
            System.out.printf("- %s (%s)%n", u.username, u.role);
        }
    }

    private void viewAudit() {
        List<AuditEntry> logs = auditStore.list();
        if (logs.isEmpty()) {
            System.out.println("No audit entries.");
            return;
        }
        System.out.println("Audit log (most recent last):");
        for (AuditEntry e : logs) {
            System.out.println(e);
        }
    }

    // --------------------------
    // Main
    // --------------------------
    public static void main(String[] args) {
        SecureFileAccessControl app = new SecureFileAccessControl();
        app.runCli();
    }
}
