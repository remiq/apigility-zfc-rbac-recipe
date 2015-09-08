# Apigility and ZfcRbac integration


You have created API application with Apigility, integrated OAuth2 authentication and now you want to add roles? Tough luck, you wouldn't find any tutorial how to do it. Till now.

## Requirements

- Working Apigility API
- Doctrine ORM
- Working authentication process using Doctrine ORM

## How it works?

We use zf-mvc-auth to handle OAuth2 authentication. We inject our listener to post authentication event, so
after successful authentication we query DB and get user's role instead of ID. 

In ZfcRbac configuration we point to our IdentityProvider that will translate zf-mvc-auth Identity into 
ZfcRbac Identity.

We add alias `ZF\MvcAuth\Authorization\AuthorizationInterface` to our Authorization, so it's method isAuthorized
is called instead of Acl.

## Setup

This setup assumes that your module is called "YourApp". Please change accordingly.

Install ZfcRbac module.
This downloads module and copies it into /vendor/zf-commons/zfc-rbac/
 
```sh
$ php composer.phar require zf-commons/zfc-rbac:~2.4
```

Add module to /config/application.config.php.
This enables module to be used by ZF2.

```php
return array(
    'modules' => array(
        // other modules ie. Doctrine
        'ZfcRbac',
        // other modules ie. Application, ZF\\Apigility
    )
);
```

Copy /vendor/zf-commons/zfc-rbac/config/zfc_rbac.global.php.dist to /config/autoload/zfc_rbac.global.php.
This will be the base of configuration you will use in next step.

Set following values in /config/autoload/zfc_rbac.global.php.
This will enable authorization only in places specified by code. If you want to block whole controller, read about guards.

```php
return array(
    'zfc_rbac' => array(
        'identity_provider'   => 'YourApp\\Rbac\\IdentityProvider',
        'guest_role' => 'guest',
        'guards' => array(),
        'protection_policy' => \ZfcRbac\Guard\GuardInterface::POLICY_ALLOW,
    )
);
```

Set role tree in /config/autoload/zfc_rbac.global.php (same file, update it).
This defines that your application have three roles: admin, user and guest.
User have permissions "canDoFoo", "canDoBar". 
Admin have all user's permission ("canDoFoo", "canDoBar") and their own "canDoBaz".

```php
return array(
    'zfc_rbac' => array(
        // our previous settings are here
        'role_provider' => array(
            'ZfcRbac\Role\InMemoryRoleProvider' =>  array(
                'admin' =>  array(
                    'children'  =>  array('user'),
                    'permissions'   =>  array(
                        'canDoBaz',
                    ),
                ),
                'user' =>  array(
                    'children'  =>  array('guest'),
                    'permissions'   =>  array(
                        'canDoFoo',
                        'canDoBar',
                    ),
                ),
                'guest' =>  array(),
            ),
        ),
    )
);
```

Set REST guard in /config/autoload/zfc_rbac.global.php (same file, update it).
It is similar to zf-mvc-auth/authorization config option, instead of boolean options (true: require authorization,
false: allow guest) it uses boolean+array (true: always allow, false: never allow, array: allow only those with selected
permission).

```php
    'rest_guard' => [
        'YourApp\\V1\\Rest\\Foo\\Controller' => [
            'entity' => [
                'GET' => true,              // everyone can use GET /foo/:id
                'POST' => false,            // nobody can use POST /foo/:id
                'PATCH' => ['canDoFoo'],    // only admin or user can use PATCH /foo/:id
                'PUT' => ['canDoFoo', 'canDoBar'], // only roles that have BOTH permissions (admin/user) can use PUT /foo/:id 
                'DELETE' => ['canDoFoo'],
            ],
            'collection' => [
                'GET' => true,          // everyone can use GET /foo
                'POST' => ['canDoFoo'], // only admin or user can use POST /foo 
                'PATCH' => false,       // nobody can use PATCH /foo
                'PUT' => false,
                'DELETE' => ['canDoBaz'], // only admin can use DELETE /foo
            ],
        ],
    ],
```

Remove 'zf-mvc-auth/authorization' branch from /module/YourApp/config/module.config.php - it's no longer used.


In /module/YourApp/config/module.config.php add following:

```php
return array(
    'service_manager' => array(
        'aliases' => array(
            'ZF\MvcAuth\Authorization\AuthorizationInterface' => 'YourApp\\Rbac\\Authorization',
        ),
        'factories' => array(
            'YourApp\\Rbac\\IdentityProvider'   =>  'YourApp\\Rbac\\IdentityProviderFactory',
            'YourApp\\Rbac\\AuthenticationListener'  =>  'YourApp\\Rbac\\AuthenticationListenerFactory',
            'YourApp\\Rbac\\Authorization'  =>  'YourApp\\Rbac\\AuthorizationFactory',
        ),
    ),
);
```

Create /module/YourApp/Rbac/IdentityProviderFactory.php.
This will create IdentityProvider service used by ZfcRbac and include OAuth2 identity resolved by token. 

```php
namespace YourApp\Rbac;

use \Zend\ServiceManager\ServiceManager;

class IdentityProviderFactory
{
    public function __invoke(ServiceManager $services)
    {
        /** @var \Zend\Authentication\AuthenticationService $authenticationProvider */
        $authenticationProvider = $services->get('authentication');

        $identityProvider = new IdentityProvider();
        $identityProvider->setAuthenticationProvider($authenticationProvider);
        return $identityProvider;
    }
}
```

Create /module/YourApp/Rbac/IdentityProvider.php.
GetIdentity function will be executed by ZfcRbac. Since it wants something different than ZF\MvcAuth\Identity, 
we have to translate. We take existing Identity, get userId (weirdly called getRoleId), then we check OAuthUserEntity
where we store users and their roles. Then we return YourApp\Rbac\Identity with a role.

```php
namespace YourApp\Rbac;

use ZfcRbac\Identity\IdentityProviderInterface;
use Zend\Authentication\AuthenticationService;

/**
 * Class IdentityProvider provides Identity object required by RBAC.
 * We return custom Identity because we connect OAuth2 authentication (returning userId) and RBAC authorization (requiring roles)
 *
 * @package YourApp\Rbac
 */
class IdentityProvider implements IdentityProviderInterface
{
    /** @var Identity $rbacIdentity */
    private $rbacIdentity = null;

    /* @var \Zend\Authentication\AuthenticationService $authenticationProvider */
    private $authenticationProvider;

    public function setAuthenticationProvider(AuthenticationService $authenticationProvider)
    {
        $this->authenticationProvider = $authenticationProvider;
        return $this;
    }

    /**
     * Checks if user is authenticated. If yes, checks db for user's role and returns Identity.
     *
     * @return Identity
     */
    public function getIdentity()
    {
        if ($this->rbacIdentity === null)
        {
            $this->rbacIdentity = new Identity();

            $mvcIdentity = $this->authenticationProvider->getIdentity();
            $role = $mvcIdentity->getRoleId();
            $this->rbacIdentity
                ->setRoles($role);
        }

        return $this->rbacIdentity;
    }
}

```

Create /module/YourApp/Rbac/Identity.php.
This creates Identity class used by ZfcRbac.

```php
namespace YourApp\Rbac;

use ZfcRbac\Identity\IdentityInterface;

class Identity implements IdentityInterface
{
    private $roles = array();

    public function setRoles($roles)
    {
        if (!is_array($roles)) {
            $roles = array($roles);
        }
        $this->roles = $roles;
        return $this;
    }

    /**
     * Get the list of roles of this identity
     *
     * @return string[]|\Rbac\Role\RoleInterface[]
     */
    public function getRoles()
    {
        return $this->roles;
    }
}
```

.Update your OAuth2 users table (oauth_users) and entity (YourApp\OAuth\OAuthUserEntity).
Add `role` VARCHAR(20) field to oauth_users table.
Add getRole function to OAuthUserEntity (or whatever you called it).
We also store role/permission constants here.

```php
namespace YourApp\OAuth;

use Doctrine\ORM\Mapping as ORM;
use Zend\Crypt\Password\Bcrypt;

/**
 * Class OAuthUserEntity
 *
 * @package YourApp\OAuth
 * @ORM\Entity()
 * @ORM\Table(name="oauth_users")
 */
class OAuthUserEntity
{
    // role tree is in /config/autoload/zfc_rbac.global.php
    const ROLE_ADMIN = 'admin';
    const ROLE_USER  = 'user';
    const ROLE_GUEST = 'guest';

    const PERMISSION_CAN_DO_FOO = 'canDoFoo';
    const PERMISSION_CAN_DO_BAR = 'canDoBar';
    const PERMISSION_CAN_DO_BAZ = 'canDoBaz';

    /**
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     * @ORM\Column(type="integer")
     * @var int
     */
    protected $user_id;

    /**
     * @ORM\Column(type="string",length=255)
     * @var string
     */
    protected $username;

    /**
     * @ORM\Column(type="string",length=255)
     * @var string
     */
    protected $password;

    /**
     * @ORM\Column(type="string",length=20)
     * @var string
     */
    protected $role;

    public function getUserId()
    {
        return $this->user_id;
    }

    public function setUsername($username)
    {
        $this->username = $username;
        return $this;
    }

    public function setPassword($password)
    {
        $this->password = (new Bcrypt())->create($password);
        return $this;
    }

    public function setRole($role)
    {
        $this->role = $role;
        return $this;
    }

    public function getRole()
    {
        return $this->role;
    }
}
```

Create /module/YourApp/Rbac/AuthenticationListenerFactory.php.
This will inject Doctrine's entity manager in our listener.

```php
namespace YourApp\Rbac;

use \Zend\ServiceManager\ServiceManager;

class AuthenticationListenerFactory
{
    public function __invoke(ServiceManager $services)
    {
        /** @var \Doctrine\ORM\EntityManager $entityManager */
        $entityManager = $services->get('Doctrine\ORM\EntityManager');
        $authenticationListener = new AuthenticationListener();
        $authenticationListener->setEntityManager($entityManager);
        return $authenticationListener;
    }
}
```

Create /module/YourApp/Rbac/AuthenticationListener.php.
This will overwrite user's ID with name of their role.

```php
namespace YourApp\Rbac;

use ZF\MvcAuth\MvcAuthEvent;
use ZF\MvcAuth\Identity\AuthenticatedIdentity;
use Doctrine\ORM\EntityManager;
use YourApp\OAuth\OAuthUserEntity;

class AuthenticationListener
{
    /** @var  EntityManager */
    private $entityManager;

    public function setEntityManager(EntityManager $entityManager)
    {
        $this->entityManager = $entityManager;
    }

    public function __invoke(MvcAuthEvent $mvcAuthEvent)
    {
        $identity = $mvcAuthEvent->getIdentity();
        if ($identity instanceof AuthenticatedIdentity)
        {
            $userId = $identity->getRoleId();
            /** @var OAuthUserEntity $oauthUserEntity */
            $oauthUserEntity = $this->entityManager->find('YourApp\OAuth\OAuthUserEntity', $userId);

            $identity->setName($oauthUserEntity->getRole());
        }
        return $identity;

    }
}

```

Add post authentication event in bootstrap in /module/YourApp/Module.php.

```php
class Module implements ApigilityProviderInterface
{
    public function onBootstrap(EventInterface $e)
    {
        /** @var Application $application */
        $application = $e->getParam('application');
        $eventManager = $application->getEventManager();
        $moduleRouteListener = new ModuleRouteListener();
        $moduleRouteListener->attach($eventManager);
        $eventManager->attach(MvcAuthEvent::EVENT_AUTHENTICATION_POST, $sm->get('YourApp\\Rbac\\AuthenticationListener'), 100);
    }
}
```

Create /modules/YourApp/Rbac/AuthorizationFactory.php
This injects ZfcRbac into our authorization and reads it's config.

```php
namespace YourApp\Rbac;

use \Zend\ServiceManager\ServiceManager;

class AuthorizationFactory
{
    public function __invoke(ServiceManager $services)
    {
        /** @var \ZfcRbac\Service\AuthorizationService $authorizationService */
        $authorizationService = $services->get('ZfcRbac\Service\AuthorizationService');

        $config = $services->get('config');
        $rbacConfig = $config['zfc_rbac'];
        $authorization = new Authorization();
        $authorization->setConfig($rbacConfig);
        $authorization->setAuthorizationService($authorizationService);
        return $authorization;
    }
}

```

Create /modules/YourApp/Rbac/Authorization.php
This enables REST guards.

```php
namespace YourApp\Rbac;

use ZF\MvcAuth\Authorization\AuthorizationInterface;
use ZF\MvcAuth\Identity\IdentityInterface;
use ZfcRbac\Service\AuthorizationService;

use ZF\ApiProblem\ApiProblem;
use ZF\ApiProblem\ApiProblemResponse;

class Authorization implements AuthorizationInterface
{
    /** @var  AuthorizationService */
    private $authorizationService;
    private $config = [];

    public function setAuthorizationService(AuthorizationService $authorizationService)
    {
        $this->authorizationService = $authorizationService;
    }

    public function setConfig(array $config)
    {
        $this->config = $config;
    }



    /**
     * Whether or not the given identity has the given privilege on the given resource.
     *
     * @param IdentityInterface $identity
     * @param mixed $resource
     * @param mixed $privilege
     * @return bool
     */
    public function isAuthorized(IdentityInterface $identity, $resource, $privilege)
    {
        $restGuard = $this->config['rest_guard'];
        list($controller, $group) = explode('::', $resource);
        if (isset($restGuard[$controller][$group][$privilege])) {
            $result = $restGuard[$controller][$group][$privilege];
            if (is_array($result)) {
                $and = true;
                foreach ($result as $r) {
                    $and = $and && $this->authorizationService->isGranted($r);
                }
                $result = $and;
            }
            return $result;
        } else {
            return new ApiProblemResponse(new ApiProblem(403, 'Acesso restrito'));
        }

        return true;
    }

}
```

# If you want to check permissions in resource...


Add service in resource factory ie. /modules/YourApp/V1/Rest/Foo/FooResourceFactory.php.

```php
namespace YourApp\V1\Rest\Foo;

class FooResourceFactory
{
    /**
     * @param \Zend\ServiceManager\ServiceManager $services
     *
     * @return PluginResource
     */
    public function __invoke($services)
    {
        /** @var \Doctrine\ORM\EntityManagerInterface $entityManager */
        $entityManager = $services->get('Doctrine\ORM\EntityManager');
        /** @var \ZfcRbac\Service\AuthorizationService $authorizationService */
        $authorizationService = $services->get('ZfcRbac\Service\AuthorizationService');

        $fooResource = new FooResource();
        $fooResource->setEntityManager($entityManager);
        $fooResource->setAuthorizationService($authorizationService);

        return $fooResource;
    }
}
```

Use authorization service in resource ie. /modules/YourApp/V1/Rest/Foo/FooResource.php.

```php
namespace YourApp\V1\Rest\Foo;

use ZF\ApiProblem\ApiProblem;
use ZfcRbac\Service\AuthorizationService;

class FooResource extends AbstractResourceListener
{
    /** @var AuthorizationService */
    protected $authorizationService;

    public function setAuthorizationService(AuthorizationService $authorizationService)
    {
        $this->authorizationService = $authorizationService;
        return $this;
    }
    
    public function create()
    {
        $authResult = $this->authorizationService->isGranted(OAuthUserEntity::PERMISSION_CAN_DO_FOO);
        if (!$authResult) {
            return new ApiProblem(403, 'You don\'t have a permission to do create Foo.');
        }
        // you have permission, create foo
    }
}
```

And that's all. 
