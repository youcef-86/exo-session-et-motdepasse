<?php 
    session_start();
    require_once 'config.php';
    var_dump('ok');
    $_GET['reg_err']="";
    if(!empty($_POST['login']) && !empty($_POST['email']) && !empty($_POST['password']) && !empty($_POST['password_retype']))
    {
        $login = htmlspecialchars($_POST['login']);
        $email = htmlspecialchars($_POST['email']);
        $password = htmlspecialchars($_POST['password']);
        $password_retype = htmlspecialchars($_POST['password_retype']);

        $check = $bdd->prepare('SELECT us_login, us_mail, us_password FROM users WHERE us_mail = ?');
        $check->execute(array($email));
        $data = $check->fetch();
        $row = $check->rowCount();
        var_dump($row);
        if($row == 0){ 
            if(strlen($login) <= 100){
                if(strlen($email) <= 100){
                    if(filter_var($email, FILTER_VALIDATE_EMAIL)){
                        if($password == $password_retype){
                        var_dump($password);
                            $cost = ['cost' => 12];
                            $password = password_hash($password, 'SHA250', PASSWORD_DEFAULT);
                            
                            $ip = $_SERVER['REMOTE_ADDR'];
                            
                            $insert = $bdd->prepare('INSERT INTO users(us_login, us_mail, us_password, us_ip) VALUES(:pseudo, :email, :password, :ip)');
                            var_dump($insert);
                            $insert->execute(array(
                                'login' => $login,
                                'mail' => $email,
                                'password' => $password,
                                'ip' => $ip
                            ));

                            header('Location:inscription.php?reg_err=success'); die();
                        }else{ header('Location: inscription.php?reg_err=password'); die();}
                    }else{ header('Location: inscription.php?reg_err=email'); die();}
                }else{ header('Location: inscription.php?reg_err=email_length'); die();}
            }else{ header('Location: inscription.php?reg_err=login_length'); die();}
        }else{ header('Location: inscription.php?reg_err=already'); die();}
    }