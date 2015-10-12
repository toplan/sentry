<?php namespace Cartalyst\Sentry\Users\Eloquent;

use Cartalyst\Sentry\Users\UserNotFoundException;
use Cartalyst\Sentry\Users\WrongPasswordException;

class ModifyProvider extends Provider
{

    /**
     * Finds a user by the login value.
     *
     * @param  string  $login
     * @return \Cartalyst\Sentry\Users\UserInterface
     * @throws \Cartalyst\Sentry\Users\UserNotFoundException
     */
    public function findByLogin($login)
    {
        $model = $this->createModel();
        $loginNames = $model->getLoginNames();
        $user = $model->newQuery()->where(function($query) use($loginNames, $login) {
            foreach ($loginNames as $loginName) {
                $query->orWhere($loginName, '=', $login);
            }
        })->first();
        if (!$user) {
            throw new UserNotFoundException("A user could not be found with a login value of [$login].");
        }
        return $user;
    }

    /**
     * Finds a user by the given credentials.
     *
     * @param  array  $credentials
     * @return \Cartalyst\Sentry\Users\UserInterface
     * @throws \Cartalyst\Sentry\Users\UserNotFoundException
     */
    public function findByCredentials(array $credentials)
    {
        $model     = $this->createModel();
        $loginNames = $model->getLoginNames();

        $passwordName = $model->getPasswordName();

        $query              = $model->newQuery();
        $hashableAttributes = $model->getHashableAttributes();
        $hashedCredentials  = array();
        foreach ($credentials as $credential => $value) {
            if (in_array($credential, $hashableAttributes)) {
                $hashedCredentials = array_merge($hashedCredentials, array($credential => $value));
            } else {
                $query = $query->where(function($query) use($loginNames, $value) {
                    foreach ($loginNames as $loginName) {
                        $query->orWhere($loginName, '=', $value);
                    }
                });
            }
        }
        if ( ! $user = $query->first()) {
            throw new UserNotFoundException("A user was not found with the given credentials.");
        }
        foreach ($hashedCredentials as $credential => $value) {
            if ( ! $this->hasher->checkhash($value, $user->{$credential})) {
                $message = "A user was found to match all plain text credentials however hashed credential [$credential] did not match.";
                if ($credential == $passwordName) {
                    throw new WrongPasswordException($message);
                }
                throw new UserNotFoundException($message);
            } elseif ($credential == $passwordName) {
                if (method_exists($this->hasher, 'needsRehashed') && $this->hasher->needsRehashed($user->{$credential})) {
                    $user->{$credential} = $value;
                    $user->save();
                }
            }
        }
        return $user;
    }

}
