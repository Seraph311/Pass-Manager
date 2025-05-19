package main;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.Toolkit;
import javax.swing.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.*;
import javax.mail.internet.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.security.MessageDigest;
import java.sql.*;
import java.util.Properties;
import java.util.Random;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

public class Main {

    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final int LOCKOUT_MINUTES = 5;

    private static final String DB_URL = "jdbc:sqlite:password_manager.db";
    private static final String EMAIL = "abreeze311@gmail.com";
    private static final String EMAIL_PASSWORD = "ctli nfaj zlwm giog";
    private static Connection connection;
    private static String currentUserEmail;
    private static String currentUserMasterKey;

    public static void main(String[] args) {
        try {
            // Load SQLite JDBC driver
            Class.forName("org.sqlite.JDBC");
            connection = DriverManager.getConnection(DB_URL);
            initializeDatabase();
            showLoginRegisterDialog();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "Database connection failed: " + e.getMessage());
            System.exit(1);
        }
    }

    // Hash Master Key
    private static String hashWithArgon2(String masterKey) {
        Argon2 argon2 = Argon2Factory.create();
        return argon2.hash(10, 65536, 1, masterKey.toCharArray());
    }

    // Verify Master Key
    private static boolean verifyArgon2Hash(String hash, String masterKey) {
        Argon2 argon2 = Argon2Factory.create();
        return argon2.verify(hash, masterKey.toCharArray());
    }

    private static void initializeDatabase() throws SQLException {
        // Create tables if they don't exist
        Statement stmt = connection.createStatement();

        // Users table (unchanged)
        stmt.execute("CREATE TABLE IF NOT EXISTS users (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "email TEXT UNIQUE NOT NULL, " +
                "password TEXT NOT NULL, " +
                "master_key TEXT NOT NULL)");

        // Vaults table (new)
        stmt.execute("CREATE TABLE IF NOT EXISTS vaults (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "user_id INTEGER NOT NULL, " +
                "name TEXT NOT NULL, " +
                "FOREIGN KEY (user_id) REFERENCES users(id))");

        // Saved passwords table (modified)
        stmt.execute("CREATE TABLE IF NOT EXISTS saved_passwords (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "user_id INTEGER NOT NULL, " +
                "vault_id INTEGER, " +  // New field
                "account_name TEXT NOT NULL, " +
                "username TEXT NOT NULL, " +
                "encrypted_password TEXT NOT NULL, " +
                "FOREIGN KEY (user_id) REFERENCES users(id), " +
                "FOREIGN KEY (vault_id) REFERENCES vaults(id))");

        // Login attempt table (unchanged)
        stmt.execute("CREATE TABLE IF NOT EXISTS login_attempts (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "email TEXT UNIQUE NOT NULL, " +
                "attempts INTEGER NOT NULL DEFAULT 0, " +
                "lockout_until INTEGER)");

        stmt.close();
    }

    private static void showLoginRegisterDialog() {
        JFrame frame = new JFrame("Password Manager");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(500, 400);
        frame.setLayout(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();

        // Login Panel
        JPanel loginPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JLabel loginTitle = new JLabel("Login", SwingConstants.CENTER);
        loginTitle.setFont(new Font("Arial", Font.BOLD, 18));
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        loginPanel.add(loginTitle, gbc);

        gbc.gridwidth = 1;
        gbc.gridy = 1;
        gbc.gridx = 0;
        loginPanel.add(new JLabel("Email:"), gbc);

        JTextField loginEmailField = new JTextField(20);
        gbc.gridx = 1;
        loginPanel.add(loginEmailField, gbc);

        gbc.gridy = 2;
        gbc.gridx = 0;
        loginPanel.add(new JLabel("Password:"), gbc);

        JPasswordField loginPasswordField = new JPasswordField(20);
        gbc.gridx = 1;
        loginPanel.add(loginPasswordField, gbc);

        JButton loginButton = new JButton("Login");
        loginButton.setBackground(new Color(70, 130, 180));
        loginButton.setForeground(Color.WHITE);
        gbc.gridy = 3;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        loginPanel.add(loginButton, gbc);

        // Register Panel
        JPanel registerPanel = new JPanel(new GridBagLayout());

        JLabel registerTitle = new JLabel("Register", SwingConstants.CENTER);
        registerTitle.setFont(new Font("Arial", Font.BOLD, 18));
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        registerPanel.add(registerTitle, gbc);

        gbc.gridwidth = 1;
        gbc.gridy = 1;
        gbc.gridx = 0;
        registerPanel.add(new JLabel("Email:"), gbc);

        JTextField registerEmailField = new JTextField(20);
        gbc.gridx = 1;
        registerPanel.add(registerEmailField, gbc);

        gbc.gridy = 2;
        gbc.gridx = 0;
        registerPanel.add(new JLabel("Password:"), gbc);

        JPasswordField registerPasswordField = new JPasswordField(20);
        gbc.gridx = 1;
        registerPanel.add(registerPasswordField, gbc);

        gbc.gridy = 3;
        gbc.gridx = 0;
        registerPanel.add(new JLabel("Master Key:"), gbc);

        JPasswordField masterKeyField = new JPasswordField(20);
        gbc.gridx = 1;
        registerPanel.add(masterKeyField, gbc);

        gbc.gridy = 4;
        gbc.gridx = 0;
        registerPanel.add(new JLabel("Confirm Key:"), gbc);

        JPasswordField confirmMasterKeyField = new JPasswordField(20);
        gbc.gridx = 1;
        registerPanel.add(confirmMasterKeyField, gbc);

        JButton registerButton = new JButton("Register");
        registerButton.setBackground(new Color(70, 130, 180));
        registerButton.setForeground(Color.WHITE);
        gbc.gridy = 5;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        registerPanel.add(registerButton, gbc);

        tabbedPane.addTab("Login", loginPanel);
        tabbedPane.addTab("Register", registerPanel);

        frame.add(tabbedPane, BorderLayout.CENTER);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

        // Login Button Action
        loginButton.addActionListener(e -> {
            String email = loginEmailField.getText();
            String password = new String(loginPasswordField.getPassword());

            if (email.isEmpty() || password.isEmpty()) {
                JOptionPane.showMessageDialog(frame, "Please fill in all fields");
                return;
            }

            try {
                if (authenticateUser(email, password)) {
                    String otp = generateOTP();
                    sendOTP(email, otp);

                    String inputOTP = JOptionPane.showInputDialog(frame, "OTP sent to your email. Please enter it:");
                    if (inputOTP != null && inputOTP.equals(otp)) {
                        currentUserEmail = email;
                        showMainApplication();
                        frame.dispose();
                    } else {
                        JOptionPane.showMessageDialog(frame, "Invalid OTP");
                    }
                } else {
                    JOptionPane.showMessageDialog(frame, "Invalid email or password");
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(frame, "Error: " + ex.getMessage());
            }
        });

        // Register Button Action
        registerButton.addActionListener(e -> {
            String email = registerEmailField.getText();
            String password = new String(registerPasswordField.getPassword());
            String masterKey = new String(masterKeyField.getPassword());
            String confirmMasterKey = new String(confirmMasterKeyField.getPassword());

            if (email.isEmpty() || password.isEmpty() || masterKey.isEmpty() || confirmMasterKey.isEmpty()) {
                JOptionPane.showMessageDialog(frame, "Please fill in all fields");
                return;
            }

            if (!masterKey.equals(confirmMasterKey)) {
                JOptionPane.showMessageDialog(frame, "Master keys don't match");
                return;
            }

            try {
                if (userExists(email)) {
                    JOptionPane.showMessageDialog(frame, "User already exists");
                    return;
                }

                String otp = generateOTP();
                sendOTP(email, otp);

                String inputOTP = JOptionPane.showInputDialog(frame, "OTP sent to your email. Please enter it:");
                if (inputOTP != null && inputOTP.equals(otp)) {
                    registerUser(email, password, masterKey);
                    currentUserEmail = email;
                    currentUserMasterKey = masterKey;
                    JOptionPane.showMessageDialog(frame, "Registration successful!");
                    tabbedPane.setSelectedIndex(0); // Switch to login tab
                } else {
                    JOptionPane.showMessageDialog(frame, "Invalid OTP");
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(frame, "Error: " + ex.getMessage());
            }
        });
    }

    private static void showMainApplication() {
        JFrame frame = new JFrame("Password Manager - " + currentUserEmail);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1000, 700); // Increased size
        frame.setLayout(new BorderLayout());

        // Top Panel with Logout Button
        JPanel topPanel = new JPanel(new BorderLayout());
        JButton logoutButton = new JButton("Logout");
        logoutButton.setBackground(new Color(220, 20, 60));
        logoutButton.setForeground(Color.WHITE);
        topPanel.add(logoutButton, BorderLayout.EAST);

        // Vault selection combo box
        JComboBox<String> vaultComboBox = new JComboBox<>();
        vaultComboBox.addItem("All Passwords"); // Default option
        JButton newVaultButton = new JButton("New Vault");
        newVaultButton.setBackground(new Color(70, 130, 180));
        newVaultButton.setForeground(Color.WHITE);
        JButton renameVaultButton = new JButton("Rename Vault");
        renameVaultButton.setBackground(new Color(70, 130, 180));
        renameVaultButton.setForeground(Color.WHITE);
        JButton deleteVaultButton = new JButton("Delete Vault");
        deleteVaultButton.setBackground(new Color(220, 20, 60));
        deleteVaultButton.setForeground(Color.WHITE);

        JPanel vaultPanel = new JPanel();
        vaultPanel.add(new JLabel("Vault:"));
        vaultPanel.add(vaultComboBox);
        vaultPanel.add(newVaultButton);
        vaultPanel.add(renameVaultButton);
        vaultPanel.add(deleteVaultButton);
        topPanel.add(vaultPanel, BorderLayout.CENTER);

        frame.add(topPanel, BorderLayout.NORTH);

        // Main Panel
        JTabbedPane tabbedPane = new JTabbedPane();

        // Add New Password Panel
        JPanel addPasswordPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JLabel addTitle = new JLabel("Add New Password", SwingConstants.CENTER);
        addTitle.setFont(new Font("Arial", Font.BOLD, 16));
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        addPasswordPanel.add(addTitle, gbc);

        gbc.gridwidth = 1;
        gbc.gridy = 1;
        gbc.gridx = 0;
        addPasswordPanel.add(new JLabel("Vault:"), gbc);

        JComboBox<String> addVaultComboBox = new JComboBox<>();
        addVaultComboBox.addItem("No Vault"); // Default option
        gbc.gridx = 1;
        addPasswordPanel.add(addVaultComboBox, gbc);

        gbc.gridy = 2;
        gbc.gridx = 0;
        addPasswordPanel.add(new JLabel("Account Name:"), gbc);

        JTextField accountNameField = new JTextField(20);
        gbc.gridx = 1;
        addPasswordPanel.add(accountNameField, gbc);

        gbc.gridy = 3;
        gbc.gridx = 0;
        addPasswordPanel.add(new JLabel("Username:"), gbc);

        JTextField usernameField = new JTextField(20);
        gbc.gridx = 1;
        addPasswordPanel.add(usernameField, gbc);

        gbc.gridy = 4;
        gbc.gridx = 0;
        addPasswordPanel.add(new JLabel("Password:"), gbc);

        JPasswordField passwordField = new JPasswordField(20);
        gbc.gridx = 1;
        addPasswordPanel.add(passwordField, gbc);

        JButton saveButton = new JButton("Save Password");
        saveButton.setBackground(new Color(70, 130, 180));
        saveButton.setForeground(Color.WHITE);
        gbc.gridy = 5;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        addPasswordPanel.add(saveButton, gbc);

        // View Passwords Panel
        JPanel viewPasswordsPanel = new JPanel(new BorderLayout());

        // Table for displaying passwords
        String[] columnNames = {"ID", "Vault", "Account Name", "Username", "Password"};
        Object[][] data = {}; // Empty data to start with

        JTable passwordTable = new JTable(data, columnNames);
        passwordTable.setDefaultEditor(Object.class, null); // Make table non-editable
        passwordTable.getColumnModel().getColumn(4).setCellRenderer(new PasswordCellRenderer());

        JScrollPane scrollPane = new JScrollPane(passwordTable);
        viewPasswordsPanel.add(scrollPane, BorderLayout.CENTER);

        // Button panel
        JPanel buttonPanel = new JPanel();
        JButton viewPasswordButton = new JButton("View Password");
        viewPasswordButton.setBackground(new Color(70, 130, 180));
        viewPasswordButton.setForeground(Color.WHITE);
        JButton copyPasswordButton = new JButton("Copy");
        copyPasswordButton.setBackground(new Color(100, 149, 237));
        copyPasswordButton.setForeground(Color.WHITE);
        JButton deletePasswordButton = new JButton("Delete");
        deletePasswordButton.setBackground(new Color(220, 20, 60));
        deletePasswordButton.setForeground(Color.WHITE);
        JButton refreshButton = new JButton("Refresh");
        refreshButton.setBackground(new Color(34, 139, 34));
        refreshButton.setForeground(Color.WHITE);

        buttonPanel.add(viewPasswordButton);
        buttonPanel.add(copyPasswordButton);
        buttonPanel.add(deletePasswordButton);
        buttonPanel.add(refreshButton);
        viewPasswordsPanel.add(buttonPanel, BorderLayout.SOUTH);

        tabbedPane.addTab("Add Password", addPasswordPanel);
        tabbedPane.addTab("View Passwords", viewPasswordsPanel);

        frame.add(tabbedPane, BorderLayout.CENTER);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

        Runnable loadVaults = () -> {
            try {
                int userId = getUserId(currentUserEmail);
                String query = "SELECT id, name FROM vaults WHERE user_id = ? ORDER BY name";

                vaultComboBox.removeAllItems();
                addVaultComboBox.removeAllItems();

                vaultComboBox.addItem("All Passwords");
                addVaultComboBox.addItem("No Vault");

                try (PreparedStatement stmt = connection.prepareStatement(query)) {
                    stmt.setInt(1, userId);
                    ResultSet rs = stmt.executeQuery();

                    while (rs.next()) {
                        String vaultName = rs.getString("name");
                        vaultComboBox.addItem(vaultName);
                        addVaultComboBox.addItem(vaultName);
                    }
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(frame, "Error loading vaults: " + ex.getMessage());
            }
        };

        // Load vaults when application starts
        loadVaults.run();

        // Load passwords when switching to view tab or on refresh
        ActionListener loadPasswordsAction = e -> {
            try {
                int userId = getUserId(currentUserEmail);
                String query;
                PreparedStatement stmt;

                String selectedVault = (String) vaultComboBox.getSelectedItem();

                if ("All Passwords".equals(selectedVault)) {
                    query = "SELECT sp.id, v.name as vault_name, sp.account_name, sp.username " +
                            "FROM saved_passwords sp " +
                            "LEFT JOIN vaults v ON sp.vault_id = v.id " +
                            "WHERE sp.user_id = ?";
                    stmt = connection.prepareStatement(query);
                    stmt.setInt(1, userId);
                } else {
                    query = "SELECT sp.id, v.name as vault_name, sp.account_name, sp.username " +
                            "FROM saved_passwords sp " +
                            "JOIN vaults v ON sp.vault_id = v.id " +
                            "WHERE sp.user_id = ? AND v.name = ?";
                    stmt = connection.prepareStatement(query);
                    stmt.setInt(1, userId);
                    stmt.setString(2, selectedVault);
                }

                java.util.List<Object[]> dataList = new java.util.ArrayList<>();

                ResultSet rs = stmt.executeQuery();
                while (rs.next()) {
                    Object[] row = new Object[5];
                    row[0] = rs.getInt("id");
                    row[1] = rs.getString("vault_name") != null ? rs.getString("vault_name") : "No Vault";
                    row[2] = rs.getString("account_name");
                    row[3] = rs.getString("username");
                    row[4] = "••••••••"; // Hidden password
                    dataList.add(row);
                }

                Object[][] newData = dataList.toArray(new Object[0][]);
                passwordTable.setModel(new DefaultTableModel(newData, columnNames) {
                    @Override
                    public boolean isCellEditable(int row, int column) {
                        return false;
                    }
                });
                passwordTable.getColumnModel().getColumn(4).setCellRenderer(new PasswordCellRenderer());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(frame, "Error loading passwords: " + ex.getMessage());
            }
        };


        // Load passwords when switching to view tab
        tabbedPane.addChangeListener(e -> {
            if (tabbedPane.getSelectedIndex() == 1) {
                loadPasswordsAction.actionPerformed(null);
            }
        });

        vaultComboBox.addActionListener(e -> {
            if (tabbedPane.getSelectedIndex() == 1) {
                loadPasswordsAction.actionPerformed(null);
            }
        });

        // Save Button Action
        saveButton.addActionListener(e -> {
            String vaultName = (String) addVaultComboBox.getSelectedItem();
            String accountName = accountNameField.getText();
            String username = usernameField.getText();
            String password = new String(passwordField.getPassword());

            if (accountName.isEmpty() || username.isEmpty() || password.isEmpty()) {
                JOptionPane.showMessageDialog(frame, "Please fill in all fields");
                return;
            }

            try {
                Integer vaultId = null;
                if (!"No Vault".equals(vaultName)) {
                    vaultId = getVaultId(currentUserEmail, vaultName);
                }

                savePassword(accountName, username, password, vaultId);
                accountNameField.setText("");
                usernameField.setText("");
                passwordField.setText("");
                JOptionPane.showMessageDialog(frame, "Password saved successfully!");
                loadPasswordsAction.actionPerformed(null); // Refresh the table
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(frame, "Error: " + ex.getMessage());
            }
        });

        // New Vault Button Action
        newVaultButton.addActionListener(e -> {
            String vaultName = JOptionPane.showInputDialog(frame, "Enter vault name:");
            if (vaultName != null && !vaultName.trim().isEmpty()) {
                try {
                    createVault(vaultName);
                    loadVaults.run();
                    JOptionPane.showMessageDialog(frame, "Vault created successfully!");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(frame, "Error: " + ex.getMessage());
                }
            }
        });

        // Rename Vault Button Action
        renameVaultButton.addActionListener(e -> {
            String selectedVault = (String) vaultComboBox.getSelectedItem();
            if (selectedVault == null || "All Passwords".equals(selectedVault)) {
                JOptionPane.showMessageDialog(frame, "Please select a vault to rename");
                return;
            }

            String newName = JOptionPane.showInputDialog(frame, "Enter new name for vault:", selectedVault);
            if (newName != null && !newName.trim().isEmpty() && !newName.equals(selectedVault)) {
                try {
                    renameVault(selectedVault, newName);
                    loadVaults.run();
                    JOptionPane.showMessageDialog(frame, "Vault renamed successfully!");
                    loadPasswordsAction.actionPerformed(null); // Refresh the table
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(frame, "Error: " + ex.getMessage());
                }
            }
        });

        // Delete Vault Button Action
        deleteVaultButton.addActionListener(e -> {
            String selectedVault = (String) vaultComboBox.getSelectedItem();
            if (selectedVault == null || "All Passwords".equals(selectedVault)) {
                JOptionPane.showMessageDialog(frame, "Please select a vault to delete");
                return;
            }

            int confirm = JOptionPane.showConfirmDialog(frame,
                    "Delete vault '" + selectedVault + "' and all passwords in it?",
                    "Confirm Delete", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                try {
                    deleteVault(selectedVault);
                    loadVaults.run();
                    JOptionPane.showMessageDialog(frame, "Vault deleted successfully!");
                    loadPasswordsAction.actionPerformed(null); // Refresh the table
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(frame, "Error: " + ex.getMessage());
                }
            }
        });


        // View Password Button Action
        viewPasswordButton.addActionListener(e -> {
            int selectedRow = passwordTable.getSelectedRow();
            if (selectedRow == -1) {
                JOptionPane.showMessageDialog(frame, "Please select a password to view");
                return;
            }

            int passwordId = (int) passwordTable.getValueAt(selectedRow, 0);

            // Modified password input dialog
            JPasswordField passwordField2 = new JPasswordField();
            passwordField2.setPreferredSize(new Dimension(200, 30));

            int option = JOptionPane.showConfirmDialog(
                    frame,
                    passwordField2,
                    "Enter your master key to view password:",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE
            );

            if (option == JOptionPane.OK_OPTION) {
                String masterKey = new String(passwordField2.getPassword());
                if (!masterKey.isEmpty()) {
                    try {
                        String decryptedPassword = getDecryptedPassword(passwordId, masterKey);

                        // Temporarily show the password in the table
                        passwordTable.setValueAt(decryptedPassword, selectedRow, 4);

                        // Set a timer to hide the password again after 5 seconds
                        Timer timer = new Timer(5000, evt -> {
                            passwordTable.setValueAt("••••••••", selectedRow, 4);
                        });
                        timer.setRepeats(false);
                        timer.start();
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(frame, "Error: " + ex.getMessage());
                    }
                }
            }
        });

        // Delete Password Button Action
        deletePasswordButton.addActionListener(e -> {
            int selectedRow = passwordTable.getSelectedRow();
            if (selectedRow == -1) {
                JOptionPane.showMessageDialog(frame, "Please select a password to delete");
                return;
            }

            int confirm = JOptionPane.showConfirmDialog(frame, "Are you sure you want to delete this password?",
                    "Confirm Delete", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                int passwordId = (int) passwordTable.getValueAt(selectedRow, 0); // ID is still first column

                try {
                    deletePassword(passwordId);
                    loadPasswordsAction.actionPerformed(null); // Refresh the table
                    JOptionPane.showMessageDialog(frame, "Password deleted successfully!");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(frame, "Error: " + ex.getMessage());
                }
            }
        });

        // Copy Password
        copyPasswordButton.addActionListener(e -> {
            int selectedRow = passwordTable.getSelectedRow();
            if (selectedRow == -1) {
                JOptionPane.showMessageDialog(frame, "Please select a password to copy");
                return;
            }

            // Get the password value from the table
            Object passwordValue = passwordTable.getValueAt(selectedRow, 4);

            // Only allow copying if the password is visible (not bullet points)
            if (passwordValue.toString().equals("••••••••")) {
                JOptionPane.showMessageDialog(frame, "Please view the password first before copying");
                return;
            }

            // Copy to clipboard
            StringSelection stringSelection = new StringSelection(passwordValue.toString());
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);

            JOptionPane.showMessageDialog(frame, "Password copied to clipboard!");
        });

        // Refresh Button Action
        refreshButton.addActionListener(loadPasswordsAction);

        // Logout Button Action
        logoutButton.addActionListener(e -> {
            currentUserEmail = null;
            currentUserMasterKey = null;
            frame.dispose();
            showLoginRegisterDialog();
        });
    }

    private static void createVault(String name) throws SQLException {
        int userId = getUserId(currentUserEmail);
        String query = "INSERT INTO vaults (user_id, name) VALUES (?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setInt(1, userId);
            stmt.setString(2, name);
            stmt.executeUpdate();
        }
    }

    private static void renameVault(String oldName, String newName) throws SQLException {
        int userId = getUserId(currentUserEmail);
        String query = "UPDATE vaults SET name = ? WHERE user_id = ? AND name = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, newName);
            stmt.setInt(2, userId);
            stmt.setString(3, oldName);
            stmt.executeUpdate();
        }
    }

    private static void deleteVault(String name) throws SQLException {
        int userId = getUserId(currentUserEmail);

        // First delete all passwords in the vault
        String deletePasswordsQuery = "DELETE FROM saved_passwords WHERE user_id = ? AND vault_id = " +
                "(SELECT id FROM vaults WHERE user_id = ? AND name = ?)";
        try (PreparedStatement stmt = connection.prepareStatement(deletePasswordsQuery)) {
            stmt.setInt(1, userId);
            stmt.setInt(2, userId);
            stmt.setString(3, name);
            stmt.executeUpdate();
        }

        // Then delete the vault itself
        String deleteVaultQuery = "DELETE FROM vaults WHERE user_id = ? AND name = ?";
        try (PreparedStatement stmt = connection.prepareStatement(deleteVaultQuery)) {
            stmt.setInt(1, userId);
            stmt.setString(2, name);
            stmt.executeUpdate();
        }
    }

    private static Integer getVaultId(String email, String vaultName) throws SQLException {
        int userId = getUserId(email);
        String query = "SELECT id FROM vaults WHERE user_id = ? AND name = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setInt(1, userId);
            stmt.setString(2, vaultName);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("id");
            }
        }
        return null;
    }

    // Check login attempt
    private static boolean checkLoginAttempts(String email) throws SQLException {
        String query = "SELECT attempts, lockout_until FROM login_attempts WHERE email = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, email);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                int attempts = rs.getInt("attempts");
                long lockoutUntil = rs.getLong("lockout_until");

                // Check if user is currently locked out
                if (lockoutUntil > 0) {
                    long currentTime = System.currentTimeMillis();
                    if (currentTime < lockoutUntil) {
                        long minutesLeft = (lockoutUntil - currentTime) / (60 * 1000);
                        JOptionPane.showMessageDialog(null,
                                "Account locked. Try again in " + minutesLeft + " minutes.");
                        return false;
                    } else {
                        // Lockout period has expired, reset attempts
                        resetLoginAttempts(email);
                    }
                } else if (attempts >= MAX_LOGIN_ATTEMPTS) {
                    // Too many attempts, lock the account
                    long lockoutTime = System.currentTimeMillis() + (LOCKOUT_MINUTES * 60 * 1000);
                    updateLoginAttempts(email, MAX_LOGIN_ATTEMPTS, lockoutTime);
                    JOptionPane.showMessageDialog(null,
                            "Too many failed attempts. Account locked for " + LOCKOUT_MINUTES + " minutes.");
                    return false;
                }
            }
        }
        return true;
    }

    // Update login attempt
    private static void updateLoginAttempts(String email, int attempts, Long lockoutUntil) throws SQLException {
        String query;
        if (lockoutUntil != null) {
            query = "INSERT OR REPLACE INTO login_attempts (email, attempts, lockout_until) VALUES (?, ?, ?)";
        } else {
            query = "INSERT OR REPLACE INTO login_attempts (email, attempts) VALUES (?, ?)";
        }

        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, email);
            stmt.setInt(2, attempts);
            if (lockoutUntil != null) {
                stmt.setLong(3, lockoutUntil);
            }
            stmt.executeUpdate();
        }
    }

    // Reset login attemp
    private static void resetLoginAttempts(String email) throws SQLException {
        String query = "DELETE FROM login_attempts WHERE email = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, email);
            stmt.executeUpdate();
        }
    }

    // Custom cell renderer to show passwords as bullets
    static class PasswordCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (column == 4) { // Password column is now column 4
                label.setText(value.toString());
            }
            return label;
        }
    }

    // Database and Encryption Methods (same as before)
    private static boolean userExists(String email) throws SQLException {
        String query = "SELECT COUNT(*) FROM users WHERE email = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, email);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        }
        return false;
    }

    private static void registerUser(String email, String password, String masterKey) throws Exception {
        String encryptedPassword = encrypt(password, masterKey);
        String hashedMasterKey = hashWithArgon2(masterKey); // Argon2 hashing

        String query = "INSERT INTO users (email, password, master_key) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, email);
            stmt.setString(2, encryptedPassword);
            stmt.setString(3, hashedMasterKey);
            stmt.executeUpdate();
        }
    }

    private static boolean authenticateUser(String email, String password) throws Exception {
        // Check if account is locked
        if (!checkLoginAttempts(email)) {
            return false;
        }

        String query = "SELECT password, master_key FROM users WHERE email = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, email);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String storedPassword = rs.getString("password");
                String storedHashedMasterKey = rs.getString("master_key");

                JPasswordField masterKeyField = new JPasswordField();
                int option = JOptionPane.showConfirmDialog(
                        null,
                        masterKeyField,
                        "Enter your master key:",
                        JOptionPane.OK_CANCEL_OPTION
                );

                if (option != JOptionPane.OK_OPTION) {
                    return false;
                }

                String masterKey = new String(masterKeyField.getPassword());

                if (!verifyArgon2Hash(storedHashedMasterKey, masterKey)) {
                    // Increment failed attempt
                    incrementFailedAttempt(email);
                    return false;
                }

                currentUserMasterKey = masterKey;
                String decryptedPassword = decrypt(storedPassword, masterKey);

                if (decryptedPassword.equals(password)) {
                    // Successful login, reset attempts
                    resetLoginAttempts(email);
                    return true;
                } else {
                    // Increment failed attempt
                    incrementFailedAttempt(email);
                    return false;
                }
            } else {
                // User not found
                incrementFailedAttempt(email);
                return false;
            }
        }
    }

    // Increment failed attempt
    private static void incrementFailedAttempt(String email) throws SQLException {
        String query = "SELECT attempts FROM login_attempts WHERE email = ?";
        int attempts = 1;

        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, email);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                attempts = rs.getInt("attempts") + 1;
            }
        }

        if (attempts >= MAX_LOGIN_ATTEMPTS) {
            // Lock the account
            long lockoutTime = System.currentTimeMillis() + (LOCKOUT_MINUTES * 60 * 1000);
            updateLoginAttempts(email, attempts, lockoutTime);
        } else {
            updateLoginAttempts(email, attempts, null);
        }
    }

    private static void savePassword(String accountName, String username, String password, Integer vaultId) throws Exception {
        String encryptedPassword = encrypt(password, currentUserMasterKey);
        int userId = getUserId(currentUserEmail);

        String query = "INSERT INTO saved_passwords (user_id, vault_id, account_name, username, encrypted_password) " +
                "VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setInt(1, userId);
            if (vaultId != null) {
                stmt.setInt(2, vaultId);
            } else {
                stmt.setNull(2, Types.INTEGER);
            }
            stmt.setString(3, accountName);
            stmt.setString(4, username);
            stmt.setString(5, encryptedPassword);
            stmt.executeUpdate();
        }
    }

    private static String getDecryptedPassword(int passwordId, String masterKey) throws Exception {
        String query = "SELECT encrypted_password FROM saved_passwords WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setInt(1, passwordId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String encryptedPassword = rs.getString("encrypted_password");
                return decrypt(encryptedPassword, masterKey);
            }
        }
        throw new Exception("Password not found");
    }

    private static void deletePassword(int passwordId) throws SQLException {
        String query = "DELETE FROM saved_passwords WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setInt(1, passwordId);
            stmt.executeUpdate();
        }
    }

    private static int getUserId(String email) throws SQLException {
        String query = "SELECT id FROM users WHERE email = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, email);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("id");
            }
        }
        throw new SQLException("User not found");
    }

    private static String encrypt(String data, String key) throws Exception {
        // Generate a random salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        // Derive a secure key
        SecretKeySpec secretKey = generateKey(key, salt);

        // Encrypt the data
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());

        // Combine salt + encrypted data
        byte[] combined = new byte[salt.length + encryptedBytes.length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(encryptedBytes, 0, combined, salt.length, encryptedBytes.length);
        return bytesToHex(combined);
    }

    private static String decrypt(String encryptedData, String key) throws Exception {
        // Extract salt and encrypted data
        byte[] combined = hexToBytes(encryptedData);
        byte[] salt = new byte[16];
        byte[] encryptedBytes = new byte[combined.length - salt.length];
        System.arraycopy(combined, 0, salt, 0, salt.length);
        System.arraycopy(combined, salt.length, encryptedBytes, 0, encryptedBytes.length);

        // Derive the key using
        SecretKeySpec secretKey = generateKey(key, salt);

        // Decrypt the data
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }


    private static SecretKeySpec generateKey(String key, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(key.toCharArray(), salt, 100000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    private static String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }

    private static void sendOTP(String recipientEmail, String otp) throws Exception {
        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");

        Session session = Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(EMAIL, EMAIL_PASSWORD);
            }
        });

        Message message = new MimeMessage(session);
        message.setFrom(new InternetAddress(EMAIL));
        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipientEmail));
        message.setSubject("Password Manager OTP");
        message.setText("Your OTP is: " + otp + "\nThis OTP is valid for a short time.");

        Transport.send(message);
    }

}