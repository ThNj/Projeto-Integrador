<?php
require_once __DIR__ . '/../config/database.php';

class AuthController {
    private $conn;

    public function __construct() {
        $database = new Database();
        $this->conn = $database->getConnection();
    }

    // Função de registro
    public function register($username, $email, $password) {
        // Verificar se o e-mail já está cadastrado
        $query = "SELECT id FROM users WHERE email = :email";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([':email' => $email]);
        if ($stmt->rowCount() > 0) {
            return ['success' => false, 'message' => 'E-mail já está cadastrado.'];
        }

        // Criar hash da senha
        $passwordHash = password_hash($password, PASSWORD_BCRYPT);

        // Inserir o novo usuário
        $query = "INSERT INTO users (username, email, password_hash) VALUES (:username, :email, :password_hash)";
        $stmt = $this->conn->prepare($query);

        try {
            $stmt->execute([
                ':username' => $username,
                ':email' => $email,
                ':password_hash' => $passwordHash
            ]);
            return ['success' => true, 'message' => 'Usuário registrado com sucesso!'];
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Erro ao registrar o usuário: ' . $e->getMessage()];
        }
    }

    // Função de login
    public function login($email, $password) {
        // Verificar se o e-mail existe
        $query = "SELECT id, username, password_hash FROM users WHERE email = :email";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([':email' => $email]);

        if ($stmt->rowCount() === 0) {
            return ['success' => false, 'message' => 'E-mail ou senha inválidos.'];
        }

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // Verificar a senha
        if (password_verify($password, $user['password_hash'])) {
            // Criar sessão do usuário
            session_start();
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];

            return ['success' => true, 'message' => 'Login realizado com sucesso!'];
        } else {
            return ['success' => false, 'message' => 'E-mail ou senha inválidos.'];
        }
    }

    // Função de logout
    public function logout() {
        session_start();
        session_destroy();
        return ['success' => true, 'message' => 'Logout realizado com sucesso!'];
    }
}
