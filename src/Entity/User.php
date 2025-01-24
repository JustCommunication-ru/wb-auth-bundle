<?php

namespace JustCommunication\AuthBundle\Entity;

use JustCommunication\AuthBundle\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Validator\Context\ExecutionContextInterface;

#[ORM\Table(name: "user")]
#[ORM\Entity(repositoryClass: UserRepository::class)]

class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    #[ORM\Column(name: 'id', type: 'bigint')]
    private int $id;

    #[ORM\Column(type: 'string', length: 20, unique: true, nullable: true)]
    private ?string $phone=null;

    #[ORM\Column(type: 'string', length: 100, unique: true, nullable: true)]
    private ?string $email=null;

    #[ORM\Column(length: 100)]
    private ?string $name=null;

    /**
     * @var string The hashed password
     */
    #[ORM\Column(name: 'password', type: 'string', length: 255, nullable: false)]
    private string $password;

    #[ORM\Column(name:"roles", type:"json", nullable:false)]
    private array $roles = [];

    /**
     * дата регистрации
     */
    #[ORM\Column(name: 'datein', type: 'datetime', nullable: false)]
    private \DateTime $datein;

    /**
     * дата входа
     */
    #[ORM\Column(name: 'dateen', type: 'datetime', nullable: false)]
    private \DateTime $dateen;

    //--------------------------------------------------------------------------------------
    #[Assert\Callback]
    public function validatePhoneAndEmail(ExecutionContextInterface $context, mixed $payload):void
    {
        //
        !$this->getPhone() && !$this->getEmail() && $context->buildViolation('Phone or email must be set')->atPath('phone')->atPath('email')->addViolation();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function setId(int $id): User
    {
        $this->id = $id;
        return $this;
    }


    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(?string $email): static
    {
        if(!empty($email)){
            $this->email = mb_substr($email, 0, 100);
        }else{
            $this->email = $email;
        }
        

        return $this;
    }

    /**
     * @return string|null
     */
    public function getName(): ?string
    {
        return $this->name;
    }

    /**
     * @param string|null $name
     * @return User
     */
    public function setName(?string $name): User
    {
        if(!empty($name)){
            $this->name = mb_substr($name, 0, 100);
        }else{
            $this->name = $name;
        }
        
        return $this;
    }

    /**
     * A visual identifier that represents this user.
     *
     * @see UserInterface
     */
    public function getUserIdentifier(): string
    {
        $ret = $this->phone;
        if(empty($ret)) $ret = $this->email;        
        return (string) $ret;
    }

    public function getUserName(): string
    {
        $ret = $this->phone;
        if(empty($ret)) $ret = $this->email;       
        return (string) $ret;
    }

    /**
     * @see UserInterface
     */
    public function getRoles(): array
    {
        $roles = $this->roles;
        // guarantee every user at least has ROLE_USER
        $roles[] = 'ROLE_USER';

        return array_unique($roles);
    }

    public function setRoles(array $roles): static
    {
        $this->roles = $roles;

        return $this;
    }

    /**
     * @see PasswordAuthenticatedUserInterface
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    public function setPassword(string $password): static
    {
        $this->password = $password;

        return $this;
    }

    /**
     * @see UserInterface
     */
    public function eraseCredentials(): void
    {
        // If you store any temporary, sensitive data on the user, clear it here
        // $this->plainPassword = null;
    }

    /**
     * @return string
     */
    public function getPhone(): ?string
    {
        return $this->phone;
    }

    /**
     * @param string $phone
     * @return User
     */
    public function setPhone(?string $phone): User
    {
        $this->phone = $phone;
        return $this;
    }

    /**
     * @return \DateTime
     */
    public function getDatein(): \DateTime
    {
        return $this->datein;
    }

    /**
     * @param \DateTime $datein
     * @return User
     */
    public function setDatein(\DateTime $datein): User
    {
        $this->datein = $datein;
        return $this;
    }

    /**
     * @return \DateTime
     */
    public function getDateen(): \DateTime
    {
        return $this->dateen;
    }

    /**
     * @param \DateTime $dateen
     * @return User
     */
    public function setDateen(\DateTime $dateen): User
    {
        $this->dateen = $dateen;
        return $this;
    }


}
