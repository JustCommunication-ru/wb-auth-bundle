<?php

namespace JustCommunication\AuthBundle\Exception;
use Exception;

enum SendCodeType: int {
    case UNKNOWN = 0;
    case TELEGRAM = 1;
    case SMS = 2;
    case EMAIL = 3;
}
/* ошибка при отправке смс на телефон */
class SendCodeException extends Exception {
    
    public function __construct($message = "", SendCodeType $code = SendCodeType::UNKNOWN) {
        
        parent::__construct($message,$code->value );
    }
    
    public function getType():SendCodeType
    {
        return SendCodeType::from($this->code);
    }
} 