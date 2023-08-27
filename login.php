<?php

require_once('functions.php');
session_start();

$pdo = connectDb();

// IPアドレスの取得
$ip_address = $_SERVER['REMOTE_ADDR'];

// ログインチェック
if(!empty($_SESSION['EXAMPLE_USER'])){
    $exampleUser = loginUpdate($ip_address,$_SESSION['EXAMPLE_USER']['id'],$pdo);
    $_SESSION = array();
    session_destroy();
    $_SESSION['EXAMPLE_USER'] = $exampleUser;
	header('Location: '.SITE_URL);
    exit;
}

if($_SERVER['REQUEST_METHOD'] !== 'POST') { // 初回アクセス時の処理

    // 自動ログイン情報があるかどうかCookieをチェック
    if(isset($_COOKIE['EXAMPLE_COOKIE'])){

        // 自動ログイン情報があればキーを取得
        $auto_login_key = $_COOKIE['EXAMPLE_COOKIE'];
        // 自動ログインキーをDBに照合
        $sql = "SELECT * FROM auto_login WHERE c_key = :c_key AND expire >= :expire LIMIT 1";
        $stmt = $pdo->prepare($sql);
        $stmt->execute(array(":c_key" => $auto_login_key,
                             ":expire" => date('Y-m-d H:i:s')));
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

            if($row) { // 照合成功

                $exampleUser = getUserbyUserId($row['user_id'], $pdo);

                if(!empty($exampleUser)){ // ユーザー情報が存在したら、ログイン情報を最新のものに上書き
                    $exampleUser = loginUpdate($ip_address,$exampleUser['id'],$pdo);
                }else{
                    $exampleUser = "";
                }

                // セッションハイジャック対策
                session_regenerate_id(true);
                // セッションにユーザー情報をセット
                $_SESSION['EXAMPLE_USER'] = $exampleUser;
                // HOME画面に遷移する
                header('Location:'.SITE_URL);

                unset($pdo);
                exit;
            }

    }elseif(!empty($_GET['token'])){ // メールに記載のURLから飛んできた場合

        if(!empty($_GET['req']) && $_GET['req'] == 'signup'){ // 新規登録メール認証URLから飛んできた場合

            $signup_token = filter_input(INPUT_GET, 'token');

            // tokenに合致するユーザーを取得 ////////////////////////////////
            $sql = "SELECT * FROM pre_user WHERE token = :token";
            $stmt = $pdo->prepare($sql);
            $stmt->execute(array(':token' => $signup_token));
            $signup_user = $stmt->fetch(PDO::FETCH_ASSOC);

            // 合致するユーザーがいなければ無効なトークンなので、処理を中断
            if(!$signup_user){
                exit('無効なURLです。手続き途中で再読み込みをしてしまった方は、お手数ですが最初からやり直してください。');
            }
            ////////////////////////////////////////////////////////////////

            // 今回はtokenの有効期間を3時間とする ////////////////////////////////
            $tokenValidPeriod = date('Y-m-d H:i:s', strtotime('-3 hour'));

            // パスワードの変更リクエストが3時間以上前の場合、有効期限切れとする
            if($signup_user['created'] < $tokenValidPeriod){
                exit('URLの有効期限切れです');
            }
            //////////////////////////////////////////////////////////////////////

            // テーブルに保存するパスワードをハッシュ化
            $hashed_password = password_hash($signup_user['user_password'], PASSWORD_DEFAULT);

            $sql = "INSERT INTO example_users(id,user_name,user_email,user_password,ip_address,last_login,created,failed_count,locked_time) VALUES (:id,:user_name,:user_email,:user_password,:ip_address,now(),now(),:failed_count,:locked_time)";
            $stmt = $pdo->prepare($sql);
            $stmt->execute(array(':id' => null,
                                 ':user_name' => $signup_user['user_name'],
                                 ':user_email' => $signup_user['user_email'],
                                 ':user_password' => $hashed_password,
                                 ':ip_address' => $ip_address,
                                 ':failed_count' => 0,
                                 ':locked_time' => null));

            // 用が済んだので、pre_userテーブルから削除
            $sql = "DELETE FROM pre_user WHERE user_email = :user_email";
            $stmt = $pdo->prepare($sql);
            $stmt->execute(array(':user_email' => $signup_user['user_email']));

            // ユーザー情報を取得
            $sql = "SELECT * FROM example_users WHERE user_email = :user_email AND user_name = :user_name";
            $stmt = $pdo->prepare($sql);
            $stmt->execute(array(':user_email' => $signup_user['user_email'],
                                 ':user_name' => $signup_user['user_name']));
            $exampleUser = $stmt->fetch(PDO::FETCH_ASSOC);

            // セッションハイジャック対策
            session_regenerate_id(true);
            $_SESSION['EXAMPLE_USER'] = $exampleUser;

            // HOME画面に遷移する
            header('Location:'.SITE_URL);


        }else{ // パスワード変更URLから飛んできた場合

            $reset_token = filter_input(INPUT_GET, 'token');

            // tokenに合致するユーザーを取得 ////////////////////////////////
            $sql = "SELECT * FROM password_resets WHERE token = :token";
            $stmt = $pdo->prepare($sql);
            $stmt->execute(array(':token' => $reset_token));
            $reset_user = $stmt->fetch(PDO::FETCH_ASSOC);

            // 合致するユーザーがいなければ無効なトークンなので、処理を中断
            if(!$reset_user){
                exit('無効なURLです。手続き途中で再読み込みをしてしまった方は、お手数ですが最初からやり直してください。');
            }
            ////////////////////////////////////////////////////////////////

            // 今回はtokenの有効期間を3時間とする ////////////////////////////////
            $tokenValidPeriod = date('Y-m-d H:i:s', strtotime('-3 hour'));

            // パスワードの変更リクエストが3時間以上前の場合、有効期限切れとする
            if($reset_user['token_sent_at'] < $tokenValidPeriod){
                exit('URLの有効期限切れです');
            }
            //////////////////////////////////////////////////////////////////////

        }

    }

    // CSRF対策
    setToken();

} else {

    // CSRF対策
    checkToken();

    // 【パスワードリセット】ボタンを押したときの処理 ////////////////////////////////////////////////////////////////
    if(isset($_POST['reset'])){
        $reset_email = filter_input(INPUT_POST, 'reset_email');
        $done['ex_reset_email'] = "";

        if(!empty(existUser($reset_email, $pdo))){

            $exampleUser = existUser($reset_email, $pdo);

            // password reset token生成
            $reset_token = sha1(uniqid(mt_rand(), true));

            $sql = "SELECT * FROM password_resets WHERE user_email = :user_email";
            $stmt = $pdo->prepare($sql);
            $stmt->execute(array(":user_email" => $reset_email));
            $ex_reset_user = $stmt->fetch(PDO::FETCH_ASSOC);

                if (!$ex_reset_user) { // 登録されていなければ、テーブルにインサート
                    $sql = "INSERT INTO password_resets(user_id, user_email, token, token_sent_at) VALUES(:user_id, :user_email, :token, now())";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute(array(':user_id' => $exampleUser['id'],
                                        ':user_email' => $reset_email,
                                        ':token' => $reset_token));
                } else {
                    // 既にフロー中の$passwordResetUserがいる場合、tokenの再発行と有効期限のリセットを行う
                    $sql = "UPDATE password_resets SET token = :token, token_sent_at = now() WHERE user_email = :user_email";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute(array(':user_email' => $reset_email,
                                        ':token' => $reset_token));
                }

            try{
                $pdo->beginTransaction();

                // 以下、mail関数でパスワードリセット用メールを送信 ////////////
                mb_language("Japanese");
                mb_internal_encoding("UTF-8");

                $url = SITE_URL."login.php?token={$reset_token}";
                $ex_url = SITE_URL;
                $ex_fromname = SITE_NAME;
                $ex_mail = OWNER_EMAIL;
                $subject = $ex_fromname." ログインパスワードリセットURL";
                $body = $ex_fromname."パスワードリセットURLです。\n3時間以内に下記URLへアクセスし、パスワードの変更を完了してください。\n\n".$url."\n\n注)このメールに覚えのない場合には、お手数ですがメールを破棄してくださいますようお願いいたします。\n\n\n【".$ex_fromname."】\n".$ex_url."\n".$ex_mail."\n";

                $headers = [
                    'MIME-Version' => '1.0',
                    'Content-Type' => 'text/plain; charset=UTF-8',
                    'Return-Path' => $ex_mail,
                    'From' => $ex_fromname.' <'.$ex_mail.'>',
                    'Sender' => $ex_fromname.' <'.$ex_mail.'>',
                    'Reply-To' => $ex_mail,
                    'Organization' => $ex_fromname,
                    'X-Sender' => $ex_mail,
                    'X-Mailer' => 'Postfix/2.10.1',
                    'X-Priority' => '3',
                    'Content-Transfer-Encoding' => 'BASE64'
                  ];
                  array_walk( $headers, function( $_val, $_key ) use ( &$header_str ) {
                      $header_str .= sprintf( "%s: %s \r\n", trim( $_key ), trim( $_val ) );
                  } );


                $isSent = mb_send_mail($reset_email, $subject, $body, $header_str);

                if(!$isSent) throw new \Exception('メール送信に失敗しました。');

                //////////////////////////////////////////////////////////////////

                // メール送信まで成功したら、password_resetsテーブルへの変更を確定
                $pdo->commit();

            }catch(PDOException $e){
                $pdo->rollBack();
                $log_text = $e->getMessage();
                LogsFile($log_text);
                exit;
            }

            $done['ex_reset_email'] = "入力されたメールアドレス宛にメールが送信されました。<br>届かない場合、メールアドレスの入力に誤りがあるか、メールアドレスが登録されていません。";

        }else{
            $done['ex_reset_email'] = "入力されたメールアドレス宛にメールが送信されました。<br>届かない場合、メールアドレスの入力に誤りがあるか、メールアドレスが登録されていません。";
        }

    // 【パスワードを変更】ボタンを押したときの処理 ////////////////////////////////////////////////////////////////
    }elseif(isset($_POST['renew_pass'])){

        $reset_token = filter_input(INPUT_POST, 'password_reset_token');
        $reset_pass = filter_input(INPUT_POST, 'reset_pass');
        $reset_pass_comf = filter_input(INPUT_POST, 'reset_pass_comf');

        $done['ex_reset_password'] = "";

        if($reset_pass !== $reset_pass_comf){
            $done['ex_reset_password'] = "新しいパスワードと確認用パスワードが一致しません。";
        }else{

            // tokenに合致するユーザーを取得
            $sql = "SELECT * FROM password_resets WHERE token = :token";
            $stmt = $pdo->prepare($sql);
            $stmt->execute(array(':token' => $reset_token));
            $reset_user = $stmt->fetch(PDO::FETCH_ASSOC);

            // どのレコードにも合致しない無効なtokenであれば、処理を中断
            if(!$reset_user) exit('無効なURLです');

            // テーブルに保存するパスワードをハッシュ化
            $hashed_password = password_hash($reset_pass, PASSWORD_DEFAULT);

            try {
                $pdo->beginTransaction();

                // 該当ユーザーのパスワードを更新
                $sql = "UPDATE example_users SET user_password = :user_password WHERE user_email = :user_email";
                $stmt = $pdo->prepare($sql);
                $stmt->execute(array(':user_password' => $hashed_password,
                                    ':user_email' => $reset_user['user_email']));

                // 用が済んだので、パスワードリセットテーブルから削除
                $sql = "DELETE FROM password_resets WHERE user_email = :user_email";
                $stmt = $pdo->prepare($sql);
                $stmt->execute(array(':user_email' => $reset_user['user_email']));

                $pdo->commit();

            } catch (PDOException $e) {
                $pdo->rollBack();
                $log_text = $e->getMessage();
                LogsFile($log_text);
                exit;
            }

            $exampleUser = existUser($reset_user['user_email'], $pdo); // ユーザーの存在確認

            if(!empty($exampleUser)){

                $exampleUser = loginUpdate($ip_address,$exampleUser['id'],$pdo);

                // ログインに成功したのでセッションにユーザデータを保存する
                $_SESSION['EXAMPLE_USER'] = $exampleUser;

                // 自動ログイン情報を一度クリアする
                if(isset($_COOKIE['EXAMPLE_COOKIE'])) {
                    $auto_login_key = $_COOKIE['EXAMPLE_COOKIE'];
                        // Cookie情報をクリア
                        setcookie('EXAMPLE_COOKIE', '', time()-86400, '/');
                        // DB情報をクリア
                        $sql = "DELETE FROM auto_login WHERE c_key = :c_key";
                        $stmt = $pdo->prepare($sql);
                        $stmt->execute(array(":c_key" => $auto_login_key));
                }

                //アカウントロック情報が残っていたらリセット
                unlock_login_account($exampleUser['user_email'], $pdo);

                // HOME画面に遷移する。
                header('Location: '.SITE_URL);
                // DBを閉じて終了
                unset($pdo);
                exit();
            }
        }

    // 【ログイン】ボタンを押したときの処理 ////////////////////////////////////////////////////////////////
    }elseif(isset($_POST['login'])){
        $ex_email = $_POST['ex_login_email'];
        $ex_password = $_POST['ex_login_password'];
        $exampleUser = checkPassword($ex_email, $ex_password, $pdo);

        $err['ex_login_email'] = "";
        $err['ex_login_password'] = "";
        $err['ex_login'] = "";

        // [メールアドレス]形式チェック
        if (!filter_var($ex_email, FILTER_VALIDATE_EMAIL)) {
            $err['ex_login_email'] = 'メールアドレスが不正です。';
        }

        // 未入力チェック
        if(empty($ex_email) || empty($ex_password)){
            if(empty($ex_email) && !empty($ex_password)){
                $err['ex_login_email'] = "メールアドレスを入力して下さい。";
                $err['ex_login_password'] = "";
            }elseif(!empty($ex_email) && empty($ex_password)){
                $err['ex_login_email'] = "";
                $err['ex_login_password'] = "パスワードを入力して下さい。";
            }else{
                $err['ex_login_email'] = "メールアドレスを入力して下さい。";
                $err['ex_login_password'] = "パスワードを入力して下さい。";
            }

        // ユーザー存在チェック
        }elseif(empty(existUser($ex_email, $pdo)) || empty($exampleUser)){
            // 失敗カウントアップ
            login_failed_count_up($ex_email, $pdo);
            // 失敗カウント取得
            $count = get_login_failed_count($ex_email, $pdo);
                // アカウントロック
                if ($count >= LOGIN_FAILED_LIMIT) {
                    lock_login_account($ex_email, $pdo);
                    get_locked_ip($ip_address, $pdo);
                    $err['ex_login'] = '所定の回数ログインに失敗したため、<br>一定時間ログインできません。';
                }else{
                    $err['ex_login'] = 'メールアドレスとパスワードが一致しません。';
                }

        // ユーザー情報が一致したら
        }elseif(!empty($exampleUser) && empty($err['ex_login_email']) && empty($err['ex_login_password']) && empty($err['ex_login'])){
            // アカウントロックチェック
            if(!empty($exampleUser['locked_time'])){
                $lock_time_diff = strtotime('now') - strtotime($exampleUser['locked_time']);

                if($lock_time_diff < LOGIN_LOCK_PERIOD){
                    // アカウントロック中の場合
                    $err['ex_login'] = "所定の回数ログインに失敗したため、<br>一定時間ログインできません。";
                } else {
                    //アカウントロック期間終了だったらロック解除
                    unlock_login_account($ex_email, $pdo);
                }
            }

            // セッションハイジャック対策
            session_regenerate_id(true);

            $exampleUser = getUserbyUserId($exampleUser['id'], $pdo);

                if(!empty($exampleUser)){
                    $exampleUser = loginUpdate($ip_address,$exampleUser['id'],$pdo);
                }else{
                    $exampleUser = "";
                }

            if(!empty($exampleUser)){

                // 自動ログイン情報を一度クリアする
                if(isset($_COOKIE['EXAMPLE_COOKIE'])) {
                    $auto_login_key = $_COOKIE['EXAMPLE_COOKIE'];
                        // Cookie情報をクリア
                        setcookie('ANALYTICS_BASEBALL', '', time()-86400, '/');
                        // DB情報をクリア
                        $sql = "DELETE FROM auto_login WHERE c_key = :c_key";
                        $stmt = $pdo->prepare($sql);
                        $stmt->execute(array(":c_key" => $auto_login_key));
                }

                // 自動ログインを希望の場合はCookieとDBに情報を登録する。
                if(!empty($_POST['auto_login'])) {
                    // 自動ログインキーを生成
                    $auto_login_key = sha1(uniqid(mt_rand(), true));
                    // Cookie登録処理
                    setcookie('ANALYTICS_BASEBALL', $auto_login_key, time()+3600*24*365, '/');
                    // DB登録処理
                    $sql = "INSERT INTO auto_login(user_id, c_key, expire, created_at, updated_at) VALUES(:user_id, :c_key, :expire, now(), now())";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute(array(":user_id" => $exampleUser['id'],
                                        ":c_key" => $auto_login_key,
                                        ":expire" => date('Y-m-d H:i:s', time()+3600*24*365)));
                }
            }

            // ログインに成功したのでセッションにユーザデータを保存する
            $_SESSION['EXAMPLE_USER'] = $exampleUser;

            // HOME画面に遷移する。
            header('Location: '.SITE_URL);
            // DBを閉じて終了
            unset($pdo);
            exit();
        }

    // 【この内容で会員登録】ボタンを押したときの処理 ////////////////////////////////////////////////////////////////
    }elseif(isset($_POST['signup'])){

        $signup_user = "";
        $signup_email = "";
        $signup_password = "";

        $err['ex_signup_username'] = "";
        $err['ex_signup_email'] = "";
        $err['ex_signup_pass'] = "";

        if(!empty($_POST['ex_user'])){
            $signup_user = $_POST['ex_user'];
                    if(!empty($_POST['ex_email'])){
                        if(filter_var($_POST['ex_email'], FILTER_VALIDATE_EMAIL)){
                            $signup_email = $_POST['ex_email'];
                            if(!empty($_POST['ex_pass'])){
                                if(preg_match("/^[a-zA-Z0-9]+$/", $_POST['ex_pass'])){
                                    if(strlen($_POST['ex_pass']) > 6){
                                        $signup_password = $_POST['ex_pass'];

                                        if(existUser($signup_email, $pdo)){

                                            $err['ex_signup_email'] = "すでに登録されているメールアドレスです。";

                                        }else{

                                            // signup token生成
                                            $signup_token = sha1(uniqid(mt_rand(), true));

                                            $sql = "INSERT INTO pre_user(id,user_name,user_email,user_password,token,created) VALUES(:id,:user_name,:user_email,:user_password,:token,now())";
                                            $stmt = $pdo->prepare($sql);
                                            $signup_user = $stmt->execute(array(':id' => null,
                                                                                ':user_name' => $signup_user,
                                                                                ':user_email' => $signup_email,
                                                                                ':user_password' => $signup_password,
                                                                                ':token' => $signup_token));

                                            try {
                                                $pdo->beginTransaction();

                                                // 以下、mail関数でメール認証メールを送信 ////////////
                                                mb_language("Japanese");
                                                mb_internal_encoding("UTF-8");

                                                $url = SITE_URL."login.php?req=signup&token={$signup_token}";
                                                $ex_url = SITE_URL;
                                                $ex_fromname = SITE_NAME;
                                                $ex_mail = OWNER_EMAIL;
                                                $subject = $ex_fromname." 新規登録用認証メール";
                                                $body = $ex_fromname."新規登録において、メールアドレスを認証するURLです。\n3時間以内に下記URLへアクセスし、メールアドレスの認証を完了してください。\n\n".$url."\n\n注)このメールに覚えのない場合には、お手数ですがメールを破棄してくださいますようお願いいたします。\n\n\n【".$ex_fromname."】\n".$ex_url."\n".$ex_mail."\n";

                                                $headers = [
                                                    'MIME-Version' => '1.0',
                                                    'Content-Type' => 'text/plain; charset=UTF-8',
                                                    'Return-Path' => $ex_mail,
                                                    'From' => $ex_fromname.' <'.$ex_mail.'>',
                                                    'Sender' => $ex_fromname.' <'.$ex_mail.'>',
                                                    'Reply-To' => $ex_mail,
                                                    'Organization' => $ex_fromname,
                                                    'X-Sender' => $ex_mail,
                                                    'X-Mailer' => 'Postfix/2.10.1',
                                                    'X-Priority' => '3',
                                                    'Content-Transfer-Encoding' => 'BASE64'
                                                    ];
                                                    array_walk( $headers, function( $_val, $_key ) use ( &$header_str ) {
                                                        $header_str .= sprintf( "%s: %s \r\n", trim( $_key ), trim( $_val ) );
                                                    } );


                                                $isSent = mb_send_mail($signup_email, $subject, $body, $header_str);

                                                if(!$isSent) throw new \Exception('メール送信に失敗しました。');

                                                //////////////////////////////////////////////////////////////////

                                                // メール送信まで成功したら、pre_userテーブルへの変更を確定
                                                $pdo->commit();

                                            } catch (PDOException $e) {
                                                $pdo->rollBack();
                                                $log_text = $e->getMessage();
                                                LogsFile($log_text);
                                                exit;
                                            }

                                            $done['ex_signup_email'] = "入力されたメールアドレス宛に認証用メールが送信されました。";
                                        }
                                    }else{
                                        $err['ex_signup_pass'] = "パスワードは6文字以上で入力してください。";
                                    }
                                }else{
                                    $err['ex_signup_pass'] = "パスワードは半角英数字で入力してください。";
                                }
                            }else{
                                $err['ex_signup_pass'] = "パスワードが入力されていません。";
                            }
                        }else{
                            $err['ex_signup_email'] = "メールアドレスの形式でない文字列です。";
                        }
                    }else{
                        $err['ex_signup_email'] = "メールアドレスが入力されていません。";
                    }
        }else{
            $err['ex_signup_username'] = "ユーザー名が入力されていません。";
        }
    }

unset($pdo);
}
?>

<?php require_once('header.php'); ?>

        <div class="container px-4 col-12 col-lg-8 d-flex h-100 align-items-center justify-content-center">
            <div class="bg-white rounded col-12 col-lg-8 mt-5 py-4 p-lg-4 d-flex justify-content-center">
                <form method="POST">
                    <h1 class="text-center mb-3 mx-auto col-10"><img src="assets/images/logo/logo.png" class="w-50"></h1>
                        <div class="d-flex flex-wrap justify-content-center align-items-center">

                            <?php if(!empty($_GET['req'])): ?>
                                <?php if($_GET['req'] === 'reset'): ?>
                                    <input type="text" placeholder="ご登録のメールアドレス" name="reset_email" class="w-75 my-1 form-control">
                                    <input type="hidden" name="token" value="<?php echo h($_SESSION['sstoken']); ?>">
                                    <button class="btn btn-danger w-50 mt-3" name="reset">パスワードリセット</button>
                                    <?php if(!empty($done['ex_reset_email'])) echo '<span class="fs-7 fw-bold mt-2 mb-0 text-danger w-75">'.$done['ex_reset_email'].'</span>'; ?>

                                <?php elseif($_GET['req'] === 'signup'): ?>
                                    <input type="text" placeholder="ユーザー名" name="ex_user" class="w-75 my-1 form-control">
                                    <?php if(!empty($err['ex_signup_username'])) echo '<span class="fs-7 fw-bold my-2 mb-3 text-danger w-75">'.$err['ex_signup_username'].'</span>'; ?>
                                    <input type="password" id="textPassword" placeholder="パスワード(半角英数字6文字以上)" name="ex_pass" class="w-75 my-1 form-control">
                                    <span id="buttonEye" class="fa fa-eye" onclick="pushHideButton()"></span>
                                    <?php if(!empty($err['ex_signup_pass'])) echo '<span class="fs-7 fw-bold my-2 mb-3 text-danger w-75">'.$err['ex_signup_pass'].'</span>'; ?>
                                    <input type="text" placeholder="メールアドレス" name="ex_email" class="w-75 my-1 form-control">
                                    <?php if(!empty($err['ex_signup_email']))
                                    { echo '<span class="fs-7 fw-bold my-2 mb-3 text-danger">'.$err['ex_signup_email'].'</span>';}elseif(!empty($done['ex_signup_email'])){echo '<span class="fs-7 fw-bold my-2 mb-3 text-danger w-75">'.$done['ex_signup_email'].'</span>';} ?>
                                    <input type="hidden" name="token" value="<?php echo h($_SESSION['sstoken']); ?>">
                                    <button class="btn btn-primary w-50 mt-3" name="signup">この内容で登録</button>

                                <?php endif; ?>

                            <?php elseif(!empty($_GET['token'])): ?>
                                <input type="password" id="textPassword2" placeholder="新しいパスワード(半角英数字6文字以上)" name="reset_pass" class="w-75 my-1 form-control">
                                <span id="buttonEye2" class="fa fa-eye" onclick="pushHideButton2()"></span>
                                <input type="password" id="textPassword" placeholder="新しいパスワード（確認）" name="reset_pass_comf" class="w-75 my-1 form-control">
                                <span id="buttonEye" class="fa fa-eye" onclick="pushHideButton()"></span>
                                <input type="hidden" name="token" value="<?php echo h($_SESSION['sstoken']); ?>">
                                <input type="hidden" name="password_reset_token" value="<?= $_GET['token'] ?>">
                                <button class="btn btn-danger w-50 mt-3" name="renew_pass">パスワード変更</button>
                                <?php if(!empty($done['ex_reset_password'])) echo '<span class="fs-7 fw-bold mt-2 mb-4 text-danger">'.$done['ex_reset_password'].'</span>'; ?>

                            <?php else: ?>
                                <input type="text" placeholder="メールアドレス" name="ex_login_email" class="w-75 my-1 form-control">
                                <?php if(!empty($err['ex_login_email'])) echo '<span class="fs-7 fw-bold my-2 mb-3 text-danger">'.$err['ex_login_email'].'</span>'; ?>
                                <input type="password" id="textPassword" placeholder="パスワード(半角英数字6文字以上)" name="ex_login_password"  class="w-75 my-1 form-control">
                                <span id="buttonEye" class="fa fa-eye" onclick="pushHideButton()"></span>
                                <?php if(!empty($err['ex_login_password'])) echo '<span class="fs-7 fw-bold my-2 text-danger">'.$err['ex_login_password'].'</span>'; ?>
                                    <div class="auto_check w-75 my-1 d-flex justify-content-center fs-7">
                                        <input type="checkbox" name="auto_login" class="auto_check">次回から自動でログイン
                                    </div>
                                <input type="hidden" name="token" value="<?php echo h($_SESSION['sstoken']); ?>">
                                <button class="btn btn-success w-75 mt-2" name="login">ログイン</button>
                                <p class="w-75 text-center" style="font-size:0.8em;"><a href="login.php?req=reset">パスワードを忘れた方はこちら</a></p>

                                <?php if(!empty($err['ex_login'])) echo '<span class="fs-7 fw-bold mt-2 mb-2 text-danger">'.$err['ex_login'].'</span>'; ?>
                                <button class="btn btn-primary w-50 mt-3" onClick="location.href='login.php?req=signup'; return false;">新規登録</button>
                            <?php endif; ?>
                        </div>
                </form>
            </div>
        </div>
<script language="javascript">

// ログイン時の目のマーク
function pushHideButton() {
    let txtPass = document.getElementById("textPassword");
    let btnEye = document.getElementById("buttonEye");
        if (txtPass.type === "text") {
            txtPass.type = "password";
            btnEye.setAttribute('data-icon', 'eye');
        } else {
            txtPass.type = "text";
            btnEye.setAttribute('data-icon', 'eye-slash');
        }
}

function pushHideButton2() {
    let txtPass2 = document.getElementById("textPassword2");
    let btnEye2 = document.getElementById("buttonEye2");
        if (txtPass2.type === "text") {
            txtPass2.type = "password";
            btnEye2.setAttribute('data-icon', 'eye');
        } else {
            txtPass2.type = "text";
            btnEye2.setAttribute('data-icon', 'eye-slash');
        }
}

document.getElementById("textPassword").onchange = function(){
    let textPassword = document.getElementById("textPassword");
    let sibling = textPassword.nextElementSibling;

    if(textPassword.value.match(/^[a-zA-Z0-9\_]+$/) && (textPassword.value.length > 5)){

        if(sibling.tagName.toLowerCase() !== 'span'){
            return false;
        }else{
            sibling.remove();
        }
    }else{
        if(sibling.tagName.toLowerCase() !== 'span'){
            addElem = document.createElement('span');
            textPassword.parentNode.insertBefore(addElem, textPassword.nextElementSibling);
            addElem.classList.add("fs-7", "fw-bold", "my-2", "mb-3", "text-danger");
            addElem.innerHTML = "パスワードは半角英数字6文字以上で入力してください。";
            return false;
        }else{
            return false;
        }
    }
};

if(document.getElementById("textPassword2")){
    document.getElementById("textPassword2").onchange = function(){
        let textPassword = document.getElementById("textPassword2");
        let sibling = textPassword.nextElementSibling;

        if(textPassword.value.match(/^[a-zA-Z0-9\_]+$/) && (textPassword.value.length > 5)){

            if(sibling.tagName.toLowerCase() !== 'span'){
                return false;
            }else{
                sibling.remove();
            }
        }else{
            if(sibling.tagName.toLowerCase() !== 'span'){
                addElem = document.createElement('span');
                textPassword.parentNode.insertBefore(addElem, textPassword.nextElementSibling);
                addElem.classList.add("fs-7", "fw-bold", "my-2", "mb-3", "text-danger");
                addElem.innerHTML = "パスワードは半角英数字6文字以上で入力してください。";
                return false;
            }else{
                return false;
            }
        }
    }
};

</script>