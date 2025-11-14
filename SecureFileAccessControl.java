import java.util.*;

class User {
    String username;
    String password;
    String role;

    User(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }
}

public class SecureFileAccessControl {

    // Store users (username → User)
    static Map<String, User> users = new HashMap<>();

    // Store files (filename → uploader)
    static Map<String, String> files = new HashMap<>();

    public static void main(String[] args) {

        // Create some sample users
        users.put("admin", new User("admin", "admin123", "ADMIN"));
        users.put("manager", new User("manager", "manager123", "MANAGER"));
        users.put("employee", new User("employee", "emp123", "EMPLOYEE"));

        Scanner sc = new Scanner(System.in);
        System.out.println("=== Secure File Access Control System ===");

        System.out.print("Enter username: ");
        String uname = sc.nextLine();

        System.out.print("Enter password: ");
        String pwd = sc.nextLine();

        User user = authenticate(uname, pwd);
        if (user == null) {
            System.out.println("Login failed! Invalid username or password.");
            return;
        }

        System.out.println("\nWelcome, " + user.username + " (" + user.role + ")");
        showMenu(user, sc);
    }

    // Validate username & password
    static User authenticate(String uname, String pwd) {
        User u = users.get(uname);
        if (u != null && u.password.equals(pwd)) {
            return u;
        }
        return null;
    }

    // Role-based menu
    static void showMenu(User user, Scanner sc) {
        int choice;
        do {
            System.out.println("\n---- Menu ----");
            System.out.println("1. View Files");

            if (user.role.equals("ADMIN") || user.role.equals("MANAGER")) {
                System.out.println("2. Upload File");
            }
            if (user.role.equals("ADMIN")) {
                System.out.println("3. Delete File");
                System.out.println("4. View Users");
            }
            System.out.println("0. Logout");
            System.out.print("Enter your choice: ");
            choice = sc.nextInt();
            sc.nextLine(); // consume newline

            switch (choice) {
                case 1:
                    viewFiles();
                    break;

                case 2:
                    if (user.role.equals("ADMIN") || user.role.equals("MANAGER"))
                        uploadFile(user, sc);
                    else
                        System.out.println("Access Denied!");
                    break;

                case 3:
                    if (user.role.equals("ADMIN"))
                        deleteFile(sc);
                    else
                        System.out.println("Access Denied!");
                    break;

                case 4:
                    if (user.role.equals("ADMIN"))
                        viewUsers();
                    else
                        System.out.println("Access Denied!");
                    break;

                case 0:
                    System.out.println("Logged out successfully!");
                    break;

                default:
                    System.out.println("Invalid choice!");
            }
        } while (choice != 0);
    }

    // File operations
    static void viewFiles() {
        if (files.isEmpty()) {
            System.out.println("No files available.");
            return;
        }
        System.out.println("Files in the system:");
        for (Map.Entry<String, String> entry : files.entrySet()) {
            System.out.println("- " + entry.getKey() + " (Uploaded by: " + entry.getValue() + ")");
        }
    }

    static void uploadFile(User user, Scanner sc) {
        System.out.print("Enter file name to upload: ");
        String fname = sc.nextLine();
        files.put(fname, user.username);
        System.out.println("File '" + fname + "' uploaded successfully!");
    }

    static void deleteFile(Scanner sc) {
        System.out.print("Enter file name to delete: ");
        String fname = sc.nextLine();
        if (files.containsKey(fname)) {
            files.remove(fname);
            System.out.println("File '" + fname + "' deleted successfully!");
        } else {
            System.out.println("File not found!");
        }
    }

    static void viewUsers() {
        System.out.println("Registered Users:");
        for (User u : users.values()) {
            System.out.println("- " + u.username + " (" + u.role + ")");
        }
    }
}
