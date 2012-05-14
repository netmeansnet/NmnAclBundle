<?php

namespace Nmn\AclBundle\Tests\Unit\Manager;

use Nmn\AclBundle\Tests\Unit\TestCase;
use Nmn\AclBundle\Manager\AclTool;
use Nmn\AclBundle\Manager\AclManager;

use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Nmn\AclBundle\Tests\Unit\Stub\Object;
use Nmn\AclBundle\Tests\Unit\Stub\Ace;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Permission\BasicPermissionMap;

class AclToolTest extends TestCase
{
    public function setUp()
    {
        $this->aclManager = $this->getMockBuilder('Nmn\AclBundle\Manager\AclManager')->disableOriginalConstructor()->getMock();
        $this->aclTool = new AclTool($this->aclManager);
        $this->object = new \stdClass();
        $this->identity = new \stdClass();
    }
    
    public function testGetCustomMask()
    {
        $mask = $this->aclTool->getCustomMask(array('view', 'edit'));
        
        $this->assertEquals(5, $mask);
    }
    
    public function testGrantCustom()
    {
        $this->aclManager->expects($this->exactly(1))->method('grant')->with($this->object, $this->identity, 7);
        $this->aclTool->grantCustom($this->object, $this->identity, 7);
    }
    
    public function testGetManager()
    {
        $manager = $this->aclTool->getManager();
        $this->assertEquals($this->aclManager, $manager);
    }
    
    public function testRevokeAll()
    {
        $this->aclManager->expects($this->exactly(1))->method('revoke')->with($this->object, $this->identity);
        $this->aclTool->revokeAll($this->object, $this->identity);
    }
    
    public function testCanCustom()
    {
        $this->aclManager->expects($this->exactly(1))->method('isGranted')->with(3, $this->object);
        $this->aclTool->canCustom($this->object, 3);
    }
    
    public function testGrantView()
    {
        $this->aclManager->expects($this->exactly(1))->method('grant')->with($this->object, $this->identity, 1);
        $this->aclTool->grantView($this->object, $this->identity);
    }
    
    public function testGrantCreate()
    {
        $this->aclManager->expects($this->exactly(1))->method('grant')->with($this->object, $this->identity, 2);
        $this->aclTool->grantCreate($this->object, $this->identity);
    }
    
    public function testGrantEdit()
    {
        $this->aclManager->expects($this->exactly(1))->method('grant')->with($this->object, $this->identity, 4);
        $this->aclTool->grantEdit($this->object, $this->identity);
    }
    
    public function testGrantDelete()
    {
        $this->aclManager->expects($this->exactly(1))->method('grant')->with($this->object, $this->identity, 8);
        $this->aclTool->grantDelete($this->object, $this->identity);
    }
    
    public function testGrantUndelete()
    {
        $this->aclManager->expects($this->exactly(1))->method('grant')->with($this->object, $this->identity, 16);
        $this->aclTool->grantUndelete($this->object, $this->identity);
    }
    
    public function testGrantOperator()
    {
        $this->aclManager->expects($this->exactly(1))->method('grant')->with($this->object, $this->identity, 32);
        $this->aclTool->grantOperator($this->object, $this->identity);
    }
    
    public function testGrantMaster()
    {
        $this->aclManager->expects($this->exactly(1))->method('grant')->with($this->object, $this->identity, 64);
        $this->aclTool->grantMaster($this->object, $this->identity);
    }
    
    public function testGrantOwner()
    {
        $this->aclManager->expects($this->exactly(1))->method('grant')->with($this->object, $this->identity, 128);
        $this->aclTool->grantOwner($this->object, $this->identity);
    }
    
    public function testCanView()
    {
        $this->aclManager->expects($this->exactly(1))->method('isGranted')->with(BasicPermissionMap::PERMISSION_VIEW, $this->object);
        $this->aclTool->canView($this->object);
    }
    
    public function testCanEdit()
    {
        $this->aclManager->expects($this->exactly(1))->method('isGranted')->with(BasicPermissionMap::PERMISSION_EDIT, $this->object);
        $this->aclTool->canEdit($this->object);
    }
    
    public function testCanCreate()
    {
        $this->aclManager->expects($this->exactly(1))->method('isGranted')->with(BasicPermissionMap::PERMISSION_CREATE, $this->object);
        $this->aclTool->canCreate($this->object);
    }
    
    public function testCanDelete()
    {
        $this->aclManager->expects($this->exactly(1))->method('isGranted')->with(BasicPermissionMap::PERMISSION_DELETE, $this->object);
        $this->aclTool->canDelete($this->object);
    }
    
    public function testCanUndelete()
    {
        $this->aclManager->expects($this->exactly(1))->method('isGranted')->with(BasicPermissionMap::PERMISSION_UNDELETE, $this->object);
        $this->aclTool->canUndelete($this->object);
    }
    
    public function testCanOperator()
    {
        $this->aclManager->expects($this->exactly(1))->method('isGranted')->with(BasicPermissionMap::PERMISSION_OPERATOR, $this->object);
        $this->aclTool->canOperator($this->object);
    }
    
    public function testCanmaster()
    {
        $this->aclManager->expects($this->exactly(1))->method('isGranted')->with(BasicPermissionMap::PERMISSION_MASTER, $this->object);
        $this->aclTool->canMaster($this->object);
    }
    
    public function testCanowner()
    {
        $this->aclManager->expects($this->exactly(1))->method('isGranted')->with(BasicPermissionMap::PERMISSION_OWNER, $this->object);
        $this->aclTool->canOwner($this->object);
    }
    
    public function testRevokeView()
    {
        $this->aclManager->expects($this->exactly(1))->method('revoke')->with($this->object, $this->identity, 1);
        $this->aclTool->revokeView($this->object, $this->identity);
    }
    
    public function testRevokeCreate()
    {
        $this->aclManager->expects($this->exactly(1))->method('revoke')->with($this->object, $this->identity, 2);
        $this->aclTool->revokeCreate($this->object, $this->identity);
    }
    
    public function testRevokeEdit()
    {
        $this->aclManager->expects($this->exactly(1))->method('revoke')->with($this->object, $this->identity, 4);
        $this->aclTool->revokeEdit($this->object, $this->identity);
    }
    
    public function testRevokeDelete()
    {
        $this->aclManager->expects($this->exactly(1))->method('revoke')->with($this->object, $this->identity, 8);
        $this->aclTool->revokeDelete($this->object, $this->identity);
    }
    
    public function testRevokeUndelete()
    {
        $this->aclManager->expects($this->exactly(1))->method('revoke')->with($this->object, $this->identity, 16);
        $this->aclTool->revokeUndelete($this->object, $this->identity);
    }
    
    public function testRevokeOperator()
    {
        $this->aclManager->expects($this->exactly(1))->method('revoke')->with($this->object, $this->identity, 32);
        $this->aclTool->revokeOperator($this->object, $this->identity);
    }
    
    public function testRevokeMaster()
    {
        $this->aclManager->expects($this->exactly(1))->method('revoke')->with($this->object, $this->identity, 64);
        $this->aclTool->revokeMaster($this->object, $this->identity);
    }
    
    public function testRevokeOwner()
    {
        $this->aclManager->expects($this->exactly(1))->method('revoke')->with($this->object, $this->identity, 128);
        $this->aclTool->revokeOwner($this->object, $this->identity);
    }
}