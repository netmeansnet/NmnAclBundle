<?php

namespace Nmn\AclBundle\Manager;

use Nmn\AclBundle\Manager\AclManager;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Acl\Permission\BasicPermissionMap;

/**
 * Description of AclTool
 *
 * @author Giorgio Cefaro
 * @author Leonardo Proietti
 * 
 */
class AclTool
{
    /**
     *
     * @var Nmn\AclBundle\Manager\AclManager 
     */
    protected $aclManager;
    
    /**
     *
     * @param AclManager $aclManager 
     */
    public function __construct(AclManager $aclManager) 
    {
        $this->aclManager = $aclManager;
    }    
    
    /**
     *
     * @param array $permissions
     * @return int 
     */
    public function getCustomMask(array $permissions)
    {
        $builder = new MaskBuilder();
        
        foreach ($permissions as $permission) {
            $builder->add($permission);
        }
        
        return $builder->get();
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity
     * @param int $mask 
     */
    public function grantCustom($object, $identity, $mask)
    {
        $this->aclManager->grant($object, $identity, $mask);
    }
    
    /**
     *
     * @param object $object
     * @return Boolean 
     */
    public function canCustom($object, $mask)
    {
        return $this->aclManager->isGranted($mask, $object);
    }
    
    /**
     *
     * @return Nmn\AclBundle\Manager\AclManager 
     */
    public function getManager()
    {
        return $this->aclManager;
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function revokeAll($object, $identity)
    {
        $this->aclManager->revoke($object, $identity);
    }

    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function grantView($object, $identity)
    {
        $this->aclManager->grant($object, $identity, MaskBuilder::MASK_VIEW);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function grantCreate($object, $identity)
    {
        $this->aclManager->grant($object, $identity, MaskBuilder::MASK_CREATE);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function grantEdit($object, $identity)
    {
        $this->aclManager->grant($object, $identity, MaskBuilder::MASK_EDIT);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function grantDelete($object, $identity)
    {
        $this->aclManager->grant($object, $identity, MaskBuilder::MASK_DELETE);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function grantUndelete($object, $identity)
    {
        $this->aclManager->grant($object, $identity, MaskBuilder::MASK_UNDELETE);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function grantOperator($object, $identity)
    {
        $this->aclManager->grant($object, $identity, MaskBuilder::MASK_OPERATOR);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function grantMaster($object, $identity)
    {
        $this->aclManager->grant($object, $identity, MaskBuilder::MASK_MASTER);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function grantOwner($object, $identity)
    {
        $this->aclManager->grant($object, $identity, MaskBuilder::MASK_OWNER);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function revokeView($object, $identity)
    {
        $this->aclManager->revoke($object, $identity, MaskBuilder::MASK_VIEW);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function revokeCreate($object, $identity)
    {
        $this->aclManager->revoke($object, $identity, MaskBuilder::MASK_CREATE);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function revokeEdit($object, $identity)
    {
        $this->aclManager->revoke($object, $identity, MaskBuilder::MASK_EDIT);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function revokeDelete($object, $identity)
    {
        $this->aclManager->revoke($object, $identity, MaskBuilder::MASK_DELETE);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function revokeUndelete($object, $identity)
    {
        $this->aclManager->revoke($object, $identity, MaskBuilder::MASK_UNDELETE);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function revokeOperator($object, $identity)
    {
        $this->aclManager->revoke($object, $identity, MaskBuilder::MASK_OPERATOR);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function revokeMaster($object, $identity)
    {
        $this->aclManager->revoke($object, $identity, MaskBuilder::MASK_MASTER);
    }
    
    /**
     *
     * @param object $object
     * @param mixed $identity 
     */
    public function revokeOwner($object, $identity)
    {
        $this->aclManager->revoke($object, $identity, MaskBuilder::MASK_OWNER);
    }
    
    /**
     *
     * @param object $object
     * @return Boolean 
     */
    public function canView($object)
    {
        return $this->aclManager->isGranted(BasicPermissionMap::PERMISSION_VIEW, $object);
    }
    
    /**
     *
     * @param object $object
     * @return Boolean 
     */
    public function canEdit($object)
    {
        return $this->aclManager->isGranted(BasicPermissionMap::PERMISSION_EDIT, $object);
    }
    
    /**
     *
     * @param object $object
     * @return Boolean 
     */
    public function canCreate($object)
    {
        return $this->aclManager->isGranted(BasicPermissionMap::PERMISSION_CREATE, $object);
    }
    
    /**
     *
     * @param object $object
     * @return Boolean 
     */
    public function canDelete($object)
    {
        return $this->aclManager->isGranted(BasicPermissionMap::PERMISSION_DELETE, $object);
    }
    
    /**
     *
     * @param object $object
     * @return Boolean 
     */
    public function canUndelete($object)
    {
        return $this->aclManager->isGranted(BasicPermissionMap::PERMISSION_UNDELETE, $object);
    }
    
    /**
     *
     * @param object $object
     * @return Boolean 
     */
    public function canOperator($object)
    {
        return $this->aclManager->isGranted(BasicPermissionMap::PERMISSION_OPERATOR, $object);
    }
    
    /**
     *
     * @param object $object
     * @return Boolean 
     */
    public function canMaster($object)
    {
        return $this->aclManager->isGranted(BasicPermissionMap::PERMISSION_MASTER, $object);
    }
    
    /**
     *
     * @param object $object
     * @return Boolean 
     */
    public function canOwner($object)
    {
        return $this->aclManager->isGranted(BasicPermissionMap::PERMISSION_OWNER, $object);
    }
}