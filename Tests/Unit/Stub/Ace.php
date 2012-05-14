<?php

namespace Nmn\AclBundle\Tests\Unit\Stub;

use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;

class Ace
{    
    private $identity;

    public function __construct($identity)
    {
        $this->identity = $identity;
    }
    
    public function getSecurityIdentity()
    {
        return new UserSecurityIdentity('username', get_class($this->identity));
    }
    
    public function getMask()
    {
        return MaskBuilder::MASK_OWNER;
    }
}