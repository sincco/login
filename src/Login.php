<?php
# NOTICE OF LICENSE
#
# This source file is subject to the Open Software License (OSL 3.0)
# that is available through the world-wide-web at this URL:
# http://opensource.org/licenses/osl-3.0.php
#
# -----------------------
# @author: Iván Miranda
# @version: 1.0.0
# -----------------------
# Control for valid user data on app
# -----------------------

namespace Sincco\Login;

final class Login extends \stdClass {
    private static $instance;
    private static $dbData;
    private static $dbConnection;

    /**
     * Sets data base information connection for the instance
     * @param array $data Database connecion ( host, user, password, dbname, type )
     */
    public static function setDatabase( $data ) {
        if(!self::$instance instanceof self)
            self::$instance = new self();
        self::$dbData = $data;
    }

    /**
     * Logout 
     * @return none
     */
    public static function logout() {
        if(!self::$instance instanceof self)
            self::$instance = new self();
        self::$instance->endSession();
    }

    /**
     * Checks if user is logged
     * @return mixed           FALSE if not logged, user data if logged
     */
    public static function isLogged() {
        if(!self::$instance instanceof self)
            self::$instance = new self();
    // Start a session (if has not been started)
        self::$instance->startSession();
    // If exists user's data in session then is logged
        if( isset( $_SESSION['sincco\login\controller'] ) ) {
            self::$instance->startSession();
            return unserialize( $_SESSION['sincco\login\controller'] );
        }
        else
            return FALSE;
    }

    /**
     * Attemps a user login
     * @param  array $userData User data ( user/email, password)
     * @return mixed           FALSE if not logged, user data if logged
     */
    public static function login( $userData ) {
        if( !self::$instance->verifyTableExists() )
            if ( !self::$instance->createTable() )
                return FALSE;
        $response = self::$instance->getUser($userData['user']);
        if( $response ) {
            $response = array_shift($response);
            if( password_verify( $userData['password'], $response['userPassword'] ) ) {
                $_SESSION['sincco\login\controller'] = serialize( $response );
            } else 
                $response = FALSE;
        }
        return $response;
    }

    /**
     * Creates a new user account
     * @param  array $userData User data (user,email,password)
     * @return boolean
     */
    public static function createUser( $userData ) {
        if(!self::$instance instanceof self)
            self::$instance = new self();
        if( !self::$instance->verifyTableExists() )
            if ( !self::$instance->createTable() )
                return FALSE;
        $id = intval( array_shift( array_shift( self::$instance->nextUserId() ) ) ) + 1;
        $userData['password'] = self::$instance->createPasswordHash( $userData['password'] );
        try {
            $sql = 'INSERT INTO __usersControl (userId,userName, userPassword, userEmail)
                VALUES(:user_id, :user_name, :user_password, :user_email)';
            $query = self::$dbConnection->prepare($sql);
            $data = array( ':user_id'=>$id,
                ':user_name'=>$userData['user'],
                ':user_email'=>$userData['email'],
                ':user_password'=>$userData['password'] );
            return $query->execute( $data );
        } catch (\PDOException $err) {
            return FALSE;
        }
    }

    public static function editUser( $userData ) {
        if(!self::$instance instanceof self)
            self::$instance = new self();
        if( !self::$instance->verifyTableExists() )
            if ( !self::$instance->createTable() )
                return FALSE;
        $id = intval( array_shift( array_shift( self::$instance->nextUserId() ) ) ) + 1;
        $userData[ 'password' ] = self::$instance->createPasswordHash( $userData[ 'password' ] );
        try {
            $sql = 'UPDATE __usersControl 
                SET userPassword=\'' . $userData[ 'password' ] . '\', userEmail=\'' . $userData[ 'email' ] . '\'
                WHERE userName=\'' . $userData[ 'user' ] . '\' OR userEmail=\'' . $userData[ 'user' ] . '\'';
            $query = self::$dbConnection->prepare($sql);
            return $query->execute();
        } catch (\PDOException $err) {
            return FALSE;
        }
    }

    /**
     * Get user data from database
     * @param  array $user User data (user,email,password)
     * @return array       User Data
     */
    public static function getUser($user) {
        $sql = 'SELECT userName, userEmail, userPassword
            FROM __usersControl
            WHERE userName = :user OR userEmail = :user
            LIMIT 1';
        $query = self::$dbConnection->prepare($sql);
        $query->execute(array(':user', $user));
        return $query->fetchAll(\PDO::FETCH_ASSOC);
    }

    /**
     * Create a token for a form to be included in post requests
     * @param  string $form Form Name
     * @return string       Token string
     */
    public static function generateFormToken($form) {
        $token = md5(uniqid(microtime(), TRUE));  
        $_SESSION['sincco\login\controller\form' . $form . '\token'] = $token; 
        return $token;
    }

    /**
     * Gets new user ID
     * @return int User ID autonumeric
     */
    private function nextUserId() {
        $sql = 'SELECT max(userId) FROM __usersControl';
        $query = self::$dbConnection->prepare($sql);
        $query->execute();
        return $query->fetchAll(\PDO::FETCH_ASSOC);
    }

    /**
     * Create a hash for a user password, if password_hash function exists, is used, 
     * otherwise this class implements a custom hash generator
     * @param  string $password Password string for user data
     * @return string           Hash for password
     */
    private function createPasswordHash($password) {
        if( function_exists( 'password_hash' ) ) {
            $opciones = [ 'cost' => 12, ];
            return password_hash($password, PASSWORD_BCRYPT, $opciones);
        }
    }

    /**
     * Checks if user data table exists
     * @return boolean
     */
    private function verifyTableExists() {
        if(!self::$dbConnection instanceof \PDO)
            self::$instance->connectDB();
        $sql = 'SELECT * FROM __usersControl LIMIT 1';
        try {
            $query = self::$dbConnection->prepare($sql);
            $query->execute();
            return TRUE;
        } catch (\PDOException $err) {
            return FALSE;
        }
    }

    /**
     * Create the table for user data
     * @return boolean
     */
    private function createTable() {
        if(!self::$dbConnection instanceof \PDO)
            self::$instance->connectDB();
        $sql = 'CREATE TABLE __usersControl (
            userId int not null,
            userName varchar(150) not null primary key,
            userEmail varchar(150),
            userPassword varchar(60),
            userStatus char(1)
        )';
        try {
            $query = self::$dbConnection->prepare($sql);
            $query->execute();
            return TRUE;
        } catch (\PDOException $err) {
            return FALSE;
        }
    }

    /**
     * Start a session for user
     * @return none 
     */
    private function startSession() {
        if(session_status() == PHP_SESSION_NONE) session_start();
    }

    /**
     * Ends a session
     * @return none
     */
    private function endSession() {
        session_destroy();
    }

    /**
     * Open a new connection with data base
     * @return PDO:Object
     */
    private function connectDB() {
        if(!isset(self::$dbData["charset"]))
            self::$dbData["charset"] = "utf8";
        $parametros = array();
        if(self::$dbData["type"] == "mysql")
            $parametros = array(\PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES '. self::$dbData["charset"]);
        else
            $parametros = array();
        try {
            switch (self::$dbData["type"]) {
                case 'sqlsrv':
                    self::$dbConnection = new \PDO(self::$dbData["type"].":Server=".self::$dbData["host"].";",
                    self::$dbData["user"], self::$dbData['password'], $parametros);
                break;
                case 'mysql':
                    self::$dbConnection = new \PDO(self::$dbData["type"].":host=".self::$dbData["host"].";dbname=".self::$dbData["dbname"],
                    self::$dbData["user"], self::$dbData['password'], $parametros);
                break;
                case 'firebird':
                    $parametros = array(
                    \PDO::FB_ATTR_TIMESTAMP_FORMAT,"%d-%m-%Y",
                    \PDO::FB_ATTR_DATE_FORMAT ,"%d-%m-%Y"
                    );
                    self::$dbConnection = new \PDO(self::$dbData["type"].":dbname=".self::$dbData["host"].self::$dbData["dbname"], self::$dbData["user"], self::$dbData['password'], $parametros);
                break;
                default:
                    self::$dbConnection = new \PDO(self::$dbData["type"].":host=".self::$dbData["host"].";dbname=".self::$dbData["dbname"],
                    self::$dbData["user"], self::$dbData['password']);
                break;
            }
            self::$dbConnection->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
            self::$dbConnection->setAttribute(\PDO::ATTR_EMULATE_PREPARES, false);
            return TRUE;
        } catch (\PDOException $err) {
            $errorInfo = sprintf( '%s: %s in %s on line %s.',
                'Database Error',
                $err,
                $err->getFile(),
                $err->getLine()
            );
            return FALSE;
        }
    }

    
    /**
     * Validates the user's registration input
     * @return bool Success status of user's registration data validation
     */
    private function checkRegistrationData()
    {
        // if no registration form submitted: exit the method
        if (!isset($_POST["register"])) {
            return false;
        }
        // validating the input
        if (!empty($_POST['user_name'])
            && strlen($_POST['user_name']) <= 64
            && strlen($_POST['user_name']) >= 2
            && preg_match('/^[a-z\d]{2,64}$/i', $_POST['user_name'])
            && !empty($_POST['user_email'])
            && strlen($_POST['user_email']) <= 64
            && filter_var($_POST['user_email'], FILTER_VALIDATE_EMAIL)
            && !empty($_POST['user_password_new'])
            && strlen($_POST['user_password_new']) >= 6
            && !empty($_POST['user_password_repeat'])
            && ($_POST['user_password_new'] === $_POST['user_password_repeat'])
        ) {
            // only this case return TRUE, only this case is valid
            return TRUE;
        } elseif (empty($_POST['user_name'])) {
            $this->feedback = "Empty Username";
        } elseif (empty($_POST['user_password_new']) || empty($_POST['user_password_repeat'])) {
            $this->feedback = "Empty Password";
        } elseif ($_POST['user_password_new'] !== $_POST['user_password_repeat']) {
            $this->feedback = "Password and password repeat are not the same";
        } elseif (strlen($_POST['user_password_new']) < 6) {
            $this->feedback = "Password has a minimum length of 6 characters";
        } elseif (strlen($_POST['user_name']) > 64 || strlen($_POST['user_name']) < 2) {
            $this->feedback = "Username cannot be shorter than 2 or longer than 64 characters";
        } elseif (!preg_match('/^[a-z\d]{2,64}$/i', $_POST['user_name'])) {
            $this->feedback = "Username does not fit the name scheme: only a-Z and numbers are allowed, 2 to 64 characters";
        } elseif (empty($_POST['user_email'])) {
            $this->feedback = "Email cannot be empty";
        } elseif (strlen($_POST['user_email']) > 64) {
            $this->feedback = "Email cannot be longer than 64 characters";
        } elseif (!filter_var($_POST['user_email'], FILTER_VALIDATE_EMAIL)) {
            $this->feedback = "Your email address is not in a valid email format";
        } else {
            $this->feedback = "An unknown error occurred.";
        }
        // default return
        return false;
    }
}