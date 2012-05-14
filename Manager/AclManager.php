<?php

namespace Nmn\AclBundle\Manager;

use Doctrine\ORM\Proxy\Proxy;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Acl\Permission\BasicPermissionMap;

use Symfony\Component\Security\Acl\Model\MutableAclProviderInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

/**
 * Description of AclManager
 *
 * @author Giorgio Cefaro
 * @author Leonardo Proietti
 * 
 */
class AclManager
{
    
    const TYPE_OBJECT = 'object';
    const TYPE_CLASS  = 'class';
    
    /**
     *
     * @var MutableAclProviderInterface 
     */
    protected $aclProvider;
    
    /**
     *
     * @var SecurityContextInterface 
     */
    protected $securityContext;
    
    /**
     *
     * @param MutableAclProviderInterface $aclProvider
     * @param SecurityContextInterface $securityContext 
     */
    public function __construct(MutableAclProviderInterface $aclProvider, SecurityContextInterface $securityContext) 
    {
        $this->aclProvider      = $aclProvider;
        $this->securityContext  = $securityContext;
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity
     * @param integer $mask 
     */
    public function grant($object, $identity, $mask, $type = self::TYPE_OBJECT)
    {
        $acl = $this->getAcl($object);      
        $securityIdentity = $this->getSecurityIdentity($identity);  
        
        if ($type == 'object') {
            $acl->insertObjectAce($securityIdentity, $mask);
        } elseif ($type == 'class') {
            $acl->insertClassAce($securityIdentity, $mask);
        }        
        
        $this->aclProvider->updateAcl($acl);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity
     */
    public function revoke($object, $identity, $mask = null, $type = self::TYPE_OBJECT)
    {
        $acl = $this->getAcl($object);
        $aces = $acl->getObjectAces();
        $securityIdentity = $this->getSecurityIdentity($identity);
                
        foreach($aces as $i => $ace) {
            if($securityIdentity->equals($ace->getSecurityIdentity()) && (null === $mask || $mask == $ace->getMask())) {             
                if ($type == 'object') {
                    $acl->deleteObjectAce($i);
                } elseif ($type == 'class') {
                    $acl->deleteClassAce($i);
                }
            }
        }
        
        $this->aclProvider->updateAcl($acl);
    }
    
    
    /**
     *
     * @param object $object
     * @param mixed $identity
     * @param integer $mask
     * @param string $type 
     */
    public function change($object, $identity, $mask, $newMask, $type = self::TYPE_OBJECT)
    {
        $this->revoke($object, $identity, $mask, $type);
        $this->grant($object, $identity, $newMask, $type);
    }
    
    /**
     *
     * @param array $attributes
     * @param object $object
     * @return Boolean 
     */
    public function isGranted($attributes, $object)
    {
        $objectIdentity = $this->getNoProxyIdentityObject($object);
        
        return $this->securityContext->isGranted($attributes, $objectIdentity);
    }
    
    /**
     *
     * @param object $object
     */
    public function deleteAcl($object)
    {
        $this->aclProvider->deleteAcl($this->getNoProxyIdentityObject($object));
    }
        
    /**
     *
     * @param type $identity
     * @return SecurityIdentityInterface
     * @throws \InvalidArgumentException 
     */
    protected function getSecurityIdentity($identity)
    {
        $securityIdentity = null;
        
        if ($identity instanceof UserInterface) {
            $securityIdentity = UserSecurityIdentity::fromAccount($identity);
        } else if ($identity instanceof TokenInterface) {
            $securityIdentity = UserSecurityIdentity::fromToken($identity);
        } else if ($identity instanceof RoleInterface || is_string($identity)) {
            $securityIdentity = new RoleSecurityIdentity($identity);
        }
        
        if (!$securityIdentity instanceof SecurityIdentityInterface) {
            throw new \Exception('Couldn\'t create a valid SecurityIdentity with the provided identity information');
        }
        
        return $securityIdentity;
    }
        
    /**
     *
     * @param object $object
     * @return ObjectIdentity 
     */
    protected function getNoProxyIdentityObject($object)
    {
        if ($object instanceof Proxy) {
            $objectIdentity = new ObjectIdentity($object->getId(), get_parent_class($object));
        } else {
            $objectIdentity = new ObjectIdentity($object->getId(), get_class($object));
        }
        
        return $objectIdentity;
    }
    
    /**
     *
     * @param type $object
     * @return Symfony\Component\Security\Acl\Domain\Acl 
     */
    protected function getAcl($object)
    {
        // creating the ACL
        $objectIdentity = $this->getNoProxyIdentityObject($object);
        try {
            $acl = $this->aclProvider->createAcl($objectIdentity);
        }catch(\Exception $e) {
            $acl = $this->aclProvider->findAcl($objectIdentity);
        }

        return $acl;
    }  
}