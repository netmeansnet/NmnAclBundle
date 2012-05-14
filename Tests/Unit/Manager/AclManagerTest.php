<?php

namespace Nmn\AclBundle\Tests\Unit\Manager;

use Nmn\AclBundle\Tests\Unit\TestCase;
use Nmn\AclBundle\Manager\AclManager as AclManager;

use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Nmn\AclBundle\Tests\Unit\Stub\Object;
use Nmn\AclBundle\Tests\Unit\Stub\Ace;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;

class AclManagerTest extends TestCase
{
    public function setUp()
    {
        $this->aclProvider      = $this->getMockBuilder('Symfony\Component\Security\Acl\Model\MutableAclProviderInterface')->disableOriginalConstructor()->getMock();
        $this->securityContext  = $this->getMockBuilder('Symfony\Component\Security\Core\SecurityContextInterface')->disableOriginalConstructor()->getMock();
        
        $this->manager = new AclManager($this->aclProvider, $this->securityContext);
        
        $this->acl = $this->getMockBuilder('Symfony\Component\Security\Acl\Model\MutableAclInterface')->disableOriginalConstructor()->getMock(); 
        $this->object = new Object();
        $this->user   = $this->getMockBuilder('Symfony\Component\Security\Core\User\UserInterface')->disableOriginalConstructor()->getMock();        
    }
    
    private function getCommons($num = 1, $numAces = 1)
    {
        $this->aces = array();        
        for ($x = 0; $x < $numAces; $x++ ) {
            $this->aces[] = new Ace($this->user);
        }
        
        $userNames = array();
        for ($x = 0; $x < $num; $x++ ) {
            $userNames[] = 'username';
        }
        
        $this->user->expects($this->exactly($num))->method('getUsername')->will(call_user_func_array(array($this, 'onConsecutiveCalls'), $userNames));   
        $this->aclProvider->expects($this->exactly($num))->method('createAcl')->will($this->onConsecutiveCalls($this->acl, $this->acl));
        $this->aclProvider->expects($this->exactly($num))->method('updateAcl')->with($this->acl);
    }
    
    public function testGrantObject()
    {        
        $this->getCommons();
        $this->acl->expects($this->exactly(1))->method('insertObjectAce')->will($this->onConsecutiveCalls(null));
               
        $this->manager->grant($this->object, $this->user, MaskBuilder::MASK_OWNER);
    }
    
    public function testGrantClass()
    {        
        $this->getCommons();
        $this->acl->expects($this->exactly(1))->method('insertClassAce')->will($this->onConsecutiveCalls(null));
               
        $this->manager->grant($this->object, $this->user, MaskBuilder::MASK_OWNER, AclManager::TYPE_CLASS);
    }
    
    public function testRevokeObject()
    {          
        $this->getCommons();
        $this->acl->expects($this->exactly(1))->method('getObjectAces')->will($this->onConsecutiveCalls($this->aces));
        $this->acl->expects($this->exactly(1))->method('deleteObjectAce');
        
        $this->manager->revoke($this->object, $this->user, MaskBuilder::MASK_OWNER);
    }
    
    public function testRevokeObjectWithoutMask()
    {          
        $this->getCommons();
        $this->acl->expects($this->exactly(1))->method('getObjectAces')->will($this->onConsecutiveCalls($this->aces));
        $this->acl->expects($this->exactly(1))->method('deleteObjectAce');
        
        $this->manager->revoke($this->object, $this->user);
    }
    
    public function testRevokeClass()
    {        
        $this->getCommons();
        $this->acl->expects($this->exactly(1))->method('getObjectAces')->will($this->onConsecutiveCalls($this->aces));
        $this->acl->expects($this->exactly(1))->method('deleteClassAce');
        
        $this->manager->revoke($this->object, $this->user, MaskBuilder::MASK_OWNER, AclManager::TYPE_CLASS);
    }
    
    public function testRevokeClassWithoutMask()
    {          
        $this->getCommons();
        $this->acl->expects($this->exactly(1))->method('getObjectAces')->will($this->onConsecutiveCalls($this->aces));
        $this->acl->expects($this->exactly(1))->method('deleteClassAce');
        
        $this->manager->revoke($this->object, $this->user, null, AclManager::TYPE_CLASS);
    }
    
    public function testIsGranted()
    {
        $this->securityContext->expects($this->exactly(1))->method('isGranted')->with(MaskBuilder::MASK_EDIT, new ObjectIdentity($this->object->getId(), get_class($this->object)));
        
        $this->manager->isGranted(MaskBuilder::MASK_EDIT, $this->object);
    }
    
    public function testChange()
    {               
        $this->getCommons(2);
        $this->acl->expects($this->exactly(1))->method('getObjectAces')->will($this->onConsecutiveCalls($this->aces));
        $this->acl->expects($this->exactly(1))->method('deleteObjectAce');
        $this->acl->expects($this->exactly(1))->method('insertObjectAce')->will($this->onConsecutiveCalls(null));
        
        $this->manager->change($this->object, $this->user, MaskBuilder::MASK_OWNER, MaskBuilder::MASK_VIEW);
    }
    
    public function deleteAcl()
    {
        $this->aclProvider->expects($this->exactly(1))->method('deleteAcl')->with(new ObjectIdentity($this->object->getId(), get_class($this->object)));
        
        $this->manager->deleteAcl($this->object);
    }
}