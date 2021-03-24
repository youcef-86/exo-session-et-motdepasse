 <?php
    session_start();
    require_once 'config.php';

    if(isset($_POST['email']) && isset($_POST['password']))
    {
        $email = htmlspecialchars($_POST['email']);
        $password = htmlspecialchars($_POST['password']);

          /*verifier si la personne est bien inscrite dans notre base*/

        $check = $bdd->prepare('SELECT us_login, us_mail, us_password FROM users WHERE us_mail = ?');
        $check->execute(array($email));
        $data = $check->fetch();
        $row = $check->rowCount();/*verifier s'il existe dans la table ou pas*/

        if($row == 1)
        {
            if(filter_var($email, FILTER_VALIDATE_EMAIL))
            {
                $password_hash = password_hash($password, 'SHA250', PASSWORD_DEFAULT);
                /*verifier si le mp saisi est celui en bdd*/
                if(password_verify($password_hash, $data['us_password']))
                {
                    $_SESSION['user'] = $data['us_login'];
                    $_SESSION['user'] = $data['us_mail'];
                    header('Location: landing.php');die();

                }else{ header('Location: formulaire_inscription.php?login_err=password'); die(); }
            }else{ header('Location: formulaire_inscription.php?login_err=email'); die(); }
        }else{ header('Location: formulaire_inscription.php?login_err=already'); die(); }
    } else header('location: formulaire_inscription.php?');
