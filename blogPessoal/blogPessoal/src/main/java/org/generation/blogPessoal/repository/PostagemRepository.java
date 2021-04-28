package org.generation.blogPessoal.repository;

import java.util.List;

import org.generation.blogPessoal.model.Postagem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PostagemRepository extends JpaRepository<Postagem, Long> { //a interface Jpa já possui os métodos get,post,put,delete

	public List<Postagem> findAllByTituloContainingIgnoreCase (String titulo); //criando nossas próprias consultas com o Query Methods
}
