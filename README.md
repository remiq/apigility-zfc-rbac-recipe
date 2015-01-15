# Apigility and ZfcRbac integration


You have created API application with Apigility, integrated OAuth2 authentication and now you want to add roles? Tough luck, you wouldn't find any tutorial how to do it. Till now.

## Requirements

- Working Apigility API
- Doctrine ORM
- Working authentication process using Doctrine ORM

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
In /module/YourApp/config/module.config.php add following:

```php
return array(
    'service_manager' => array(
        'factories' => array(
            'YourApp\\Rbac\\IdentityProvider'   =>  'YourApp\\Rbac\\IdentityProviderFactory',
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
        /** @var \Doctrine\ORM\EntityManager $entityManager */
        $entityManager = $services->get('Doctrine\ORM\EntityManager');
        /** @var \ZF\MvcAuth\Identity\IdentityInterface $identity */
        $identity = $services->get('api-identity');

        $identityProvider = new IdentityProvider();
        $identityProvider
            ->setEntityManager($entityManager)
            ->setIdentity($identity);
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

use Doctrine\ORM\EntityManager;
use YourApp\OAuth\OAuthUserEntity;
use ZfcRbac\Identity\IdentityProviderInterface;

/**
 * Class IdentityProvider provides Identity object required by RBAC.
 * We return custom Identity because we connect OAuth2 authentication (returning userId) and RBAC authorization (requiring roles)
 *
 * @package YourApp\Rbac
 */
class IdentityProvider implements IdentityProviderInterface
{
    /** @var  EntityManager */
    protected $entityManager;

    /** @var \ZF\MvcAuth\Identity\IdentityInterface $identity */
    private $identity;


    public function setEntityManager(EntityManager $entityManager)
    {
        $this->entityManager = $entityManager;
        return $this;
    }

    public function setIdentity($identity)
    {
        /** @var \ZF\MvcAuth\Identity\IdentityInterface $identity */
        $this->identity = $identity;
        return $this;
    }

    /**
     * Checks if user is authenticated. If yes, checks db for user's role and returns Identity.
     *
     * @return Identity
     * @throws \Doctrine\ORM\ORMException
     * @throws \Doctrine\ORM\OptimisticLockException
     * @throws \Doctrine\ORM\TransactionRequiredException
     */
    public function getIdentity()
    {
        $identity = new Identity();

        $userId = $this->identity->getRoleId();
        if (!is_numeric($userId)) {
            return $identity;
        }
        $oauthUserEntity = $this->entityManager->find('YourApp\OAuth\OAuthUserEntity', $userId);
        if (!$oauthUserEntity) {
            return $identity;
        }
        /** @var OAuthUserEntity $oauthUserEntity */

        $identity->setUserId($userId)
            ->setRoles($oauthUserEntity->getRole());
        return $identity;
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
    private $userId = 0;
    private $roles = array();

    public function setUserId($userId)
    {
        $this->userId = $userId;
        return $this;
    }

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
namespace Pds\V1\Rest\Plugin;

use ZF\ApiProblem\ApiProblem;
use ZfcRbac\Service\AuthorizationService;

class PluginResource extends AbstractResourceListener
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
